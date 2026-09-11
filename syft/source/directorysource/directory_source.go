package directorysource

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/opencontainers/go-digest"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var (
	_ source.Source       = (*directorySource)(nil)
	_ source.PathExcluder = (*directorySource)(nil)
)

type Config struct {
	Path    string
	Base    string
	Exclude source.ExcludeConfig
	Alias   source.Alias
}

type directorySource struct {
	id       artifact.ID
	config   Config
	resolver file.Resolver
	mutex    *sync.Mutex
}

func NewFromPath(path string) (source.Source, error) {
	return New(Config{Path: path})
}

func New(cfg Config) (source.Source, error) {
	fileMeta, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", cfg.Path, err)
	}

	if !fileMeta.IsDir() {
		return nil, fmt.Errorf("given path is not a directory: %q", cfg.Path)
	}

	return &directorySource{
		id:     deriveIDFromDirectory(cfg),
		config: cfg,
		mutex:  &sync.Mutex{},
	}, nil
}

func (s directorySource) ID() artifact.ID {
	return s.id
}

func (s directorySource) Describe() source.Description {
	name := cleanDirPath(s.config.Path, s.config.Base)
	version := ""
	supplier := ""
	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}

		if a.Version != "" {
			version = a.Version
		}

		if a.Supplier != "" {
			supplier = a.Supplier
		}
	}
	return source.Description{
		ID:       string(s.id),
		Name:     name,
		Version:  version,
		Supplier: supplier,
		Metadata: source.DirectoryMetadata{
			Path: s.config.Path,
			Base: s.config.Base,
		},
	}
}

func (s *directorySource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		return s.resolver, nil
	}

	exclusionFunctions, err := GetDirectoryExclusionFunctions(s.config.Path, s.config.Exclude.Paths)
	if err != nil {
		return nil, err
	}

	// this should be the only file resolver that might have overlap with where files are cached
	exclusionFunctions = append(exclusionFunctions, excludeCachePathVisitors()...)

	res, err := fileresolver.NewFromDirectory(s.config.Path, s.config.Base, exclusionFunctions...)
	if err != nil {
		return nil, fmt.Errorf("unable to create directory resolver: %w", err)
	}

	s.resolver = res
	return s.resolver, nil
}

// ExcludedPaths returns a copy of the exclusion patterns this source was configured with, so a
// consumer indexing content taken from it can honor the same patterns. A copy, because
// GetDirectoryExclusionFunctions rewrites the patterns it is given.
func (s directorySource) ExcludedPaths() []string {
	return slices.Clone(s.config.Exclude.Paths)
}

func (s *directorySource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.resolver = nil
	return nil
}

func GetDirectoryExclusionFunctions(root string, exclusions []string) ([]fileresolver.PathIndexVisitor, error) {
	if len(exclusions) == 0 {
		return nil, nil
	}

	// the indexer reports an absolute, symlink-resolved path to every visitor: the resolver normalizes
	// its root with EvalSymlinks (fileresolver.NormalizeRootDirectory, via the chroot context) and the
	// walk then takes filepath.Abs of it. The root these patterns are anchored to has to be derived
	// the same way or they anchor to a path the walk never reports - on macOS a scan of a directory
	// under /var, a symlink to /private/var, would exclude nothing at all.
	//
	// A root that cannot be resolved is left as it was rather than failing the scan: EvalSymlinks
	// wants the path to exist, and the resolver reports a missing root far better than this can.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}

	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// this handles Windows file paths by converting them to C:/something/else format
	root = filepath.ToSlash(root)

	if !strings.HasSuffix(root, "/") {
		root += "/"
	}

	// the rooted patterns are built into a new slice rather than written back over the caller's:
	// the patterns belong to the source's configuration, which is read elsewhere (see
	// source.PathExcluder), and rewriting them in place would replace what the user configured with
	// scan-root-absolute patterns as a side effect of building the resolver
	rooted := make([]string, 0, len(exclusions))
	var errors []string
	for _, exclusion := range exclusions {
		// check exclusions for supported paths, these are all relative to the "scan root"
		if strings.HasPrefix(exclusion, "./") || strings.HasPrefix(exclusion, "*/") || strings.HasPrefix(exclusion, "**/") {
			exclusion = strings.TrimPrefix(exclusion, "./")
			// a trailing slash signals a directory but is otherwise discarded by doublestar.Match,
			// causing the pattern to silently match nothing (see issue #4839)
			exclusion = strings.TrimSuffix(exclusion, "/")
			rooted = append(rooted, root+exclusion)
		} else {
			errors = append(errors, exclusion)
		}
	}

	if errors != nil {
		return nil, fmt.Errorf("invalid exclusion pattern(s): '%s' (must start with one of: './', '*/', or '**/')", strings.Join(errors, "', '"))
	}

	return []fileresolver.PathIndexVisitor{
		func(_, path string, info os.FileInfo, _ error) error {
			for _, exclusion := range rooted {
				// this is required to handle Windows filepaths
				path = filepath.ToSlash(path)
				matches, err := doublestar.Match(exclusion, path)
				if err != nil {
					return nil
				}
				if matches {
					if info != nil && info.IsDir() {
						return filepath.SkipDir
					}
					return fileresolver.ErrSkipPath
				}
			}
			return nil
		},
	}, nil
}

// deriveIDFromDirectory generates an artifact ID from the given directory config. If an alias is provided, then
// the artifact ID is derived exclusively from the alias name and version. Otherwise, the artifact ID is derived
// from the path provided with an attempt to prune a prefix if a base is given. Since the contents of the directory
// are not considered, there is no semantic meaning to the artifact ID -- this is why the alias is preferred without
// consideration for the path.
func deriveIDFromDirectory(cfg Config) artifact.ID {
	var info string
	if !cfg.Alias.IsEmpty() {
		// don't use any of the path information -- instead use the alias name and version as the artifact ID.
		// why? this allows the user to set a dependable stable value for the artifact ID in case the
		// scanning root changes (e.g. a user scans a directory, then moves it to a new location and scans again).
		info = fmt.Sprintf("%s@%s", cfg.Alias.Name, cfg.Alias.Version)
	} else {
		log.Warn("no explicit name and version provided for directory source, deriving artifact ID from the given path (which is not ideal)")
		info = cleanDirPath(cfg.Path, cfg.Base)
	}

	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(filepath.Clean(info)).String())
}

func cleanDirPath(path, base string) string {
	if path == base {
		return path
	}

	if base != "" {
		cleanRoot, rootErr := fileresolver.NormalizeRootDirectory(path)
		cleanBase, baseErr := fileresolver.NormalizeBaseDirectory(base)

		if rootErr == nil && baseErr == nil {
			// allows for normalizing inputs:
			//   cleanRoot: /var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/TestDirectoryEncoder1121632790/001/some/path
			//   cleanBase: /var/folders/8x/gw98pp6535s4r8drc374tb1r0000gn/T/TestDirectoryEncoder1121632790/001
			//   normalized: some/path

			relPath, err := filepath.Rel(cleanBase, cleanRoot)
			if err == nil {
				path = relPath
			}
			// this is odd, but this means we can't use base
		}
		// if the base is not a valid chroot, then just use the path as-is
	}

	return path
}
