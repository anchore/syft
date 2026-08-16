package snapsource

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/OneOfOne/xxhash"
	diskFile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/afero"

	"github.com/anchore/clio"
	"github.com/anchore/go-homedir"
	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/bus"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*snapSource)(nil)

type Config struct {
	ID clio.Identification

	Request          string
	Platform         *image.Platform
	Exclude          source.ExcludeConfig
	DigestAlgorithms []crypto.Hash
	Alias            source.Alias

	fs afero.Fs
}

type snapSource struct {
	id               artifact.ID
	config           Config
	resolver         file.Resolver
	mutex            *sync.Mutex
	manifest         snapManifest
	digests          []file.Digest
	fs               filesystem.FileSystem
	squashfsPath     string
	squashFileCloser func() error
	closer           func() error
}

func NewFromLocal(cfg Config) (source.Source, error) {
	f, err := getLocalSnapFile(&cfg)
	if err != nil {
		return nil, err
	}
	return newFromPath(cfg, f)
}

func getLocalSnapFile(cfg *Config) (*snapFile, error) {
	expandedPath, err := homedir.Expand(cfg.Request)
	if err != nil {
		return nil, fmt.Errorf("unable to expand path %q: %w", cfg.Request, err)
	}
	cfg.Request = filepath.Clean(expandedPath)

	if cfg.fs == nil {
		cfg.fs = afero.NewOsFs()
	}

	if !fileExists(cfg.fs, cfg.Request) {
		return nil, fmt.Errorf("snap file %q does not exist", cfg.Request)
	}

	log.WithFields("path", cfg.Request).Debug("snap is a local file")

	return newSnapFromFile(context.Background(), cfg.fs, *cfg)
}

func NewFromRemote(cfg Config) (source.Source, error) {
	expandedPath, err := homedir.Expand(cfg.Request)
	if err != nil {
		return nil, fmt.Errorf("unable to expand path %q: %w", cfg.Request, err)
	}
	cfg.Request = filepath.Clean(expandedPath)

	if cfg.fs == nil {
		cfg.fs = afero.NewOsFs()
	}

	client := intFile.NewGetter(cfg.ID, cleanhttp.DefaultClient())
	f, err := getRemoteSnapFile(context.Background(), cfg.fs, client, cfg)
	if err != nil {
		return nil, err
	}

	return newFromPath(cfg, f)
}

func newFromPath(cfg Config, f *snapFile) (source.Source, error) {
	s := &snapSource{
		id:           deriveID(cfg.Request, cfg.Alias.Name, cfg.Alias.Version, f.Digests),
		config:       cfg,
		mutex:        &sync.Mutex{},
		digests:      f.Digests,
		squashfsPath: f.Path,
		closer:       f.Cleanup,
	}

	if err := s.extractManifest(); err != nil {
		// It is tried on any path ending in .snap or .squashfs, so declining one is routine and
		// a later provider usually succeeds. When the user asked for --from snap there is no
		// fallback and this error reaches them intact.
		log.WithFields("error", err, "path", f.Path).Debug("unable to read snap")

		// never hand back a source alongside an error: callers that discard the source on error would
		// leave behind the open squashfs file and the temp directory holding a downloaded snap
		if closeErr := s.Close(); closeErr != nil {
			log.WithFields("error", closeErr, "path", f.Path).Warn("unable to clean up snap source")
		}
		return nil, err
	}

	return s, nil
}

func (s *snapSource) extractManifest() error {
	r, err := s.FileResolver(source.SquashedScope)
	if err != nil {
		return fmt.Errorf("unable to create snap file resolver: %w", err)
	}

	// a manifest problem must never fail the source. this source is the only provider that can descend
	// into squashfs (filesource cannot), so returning an error here would fall through to a provider
	// that reports zero packages for a payload that has plenty. describe what we can instead.
	manifest, err := parseManifest(r)
	switch {
	case errors.Is(err, errNoManifest):
		// not every squashfs payload is a snap, and one without a manifest is still worth cataloging
		log.WithFields("path", s.squashfsPath).Debug("no snap manifest file found")
		return nil
	case err != nil:
		// the manifest is there but unusable, which is worth surfacing: the SBOM will have no source
		// name or version to show for it
		log.WithFields("error", err, "path", s.squashfsPath).Warn("unable to parse snap manifest file")
		return nil
	}

	s.manifest = *manifest

	if s.manifest.Name == "" || s.manifest.Version == "" {
		log.WithFields("path", s.squashfsPath).Warn("snap manifest is missing name or version")
	}
	return nil
}

func (s snapSource) ID() artifact.ID {
	return s.id
}

func (s snapSource) NameVersion() (string, string) {
	name := s.manifest.Name
	version := s.manifest.Version
	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}

		if a.Version != "" {
			version = a.Version
		}
	}
	return name, version
}

func (s snapSource) Describe() source.Description {
	name, version := s.NameVersion()
	return source.Description{
		ID:      string(s.id),
		Name:    name,
		Version: version,
		Metadata: source.SnapMetadata{
			Summary:       s.manifest.Summary,
			Base:          s.manifest.Base,
			Grade:         s.manifest.Grade,
			Confinement:   s.manifest.Confinement,
			Architectures: s.manifest.Architectures,
			Digests:       s.digests,
		},
	}
}

// Close releases everything the source holds. Every step runs even if an earlier one fails, since
// bailing early would skip the temp directory removal and leave a downloaded snap on disk. Safe to
// call more than once.
func (s *snapSource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var errs error
	if s.squashFileCloser != nil {
		if err := s.squashFileCloser(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("unable to close snap resolver: %w", err))
		}
		s.squashFileCloser = nil
	}
	s.resolver = nil
	if s.fs != nil {
		if err := s.fs.Close(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("unable to close snap squashfs: %w", err))
		}
		s.fs = nil
	}
	if s.closer != nil {
		if err := s.closer(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("unable to close snap source: %w", err))
		}
		s.closer = nil
	}
	return errs
}

func (s *snapSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		return s.resolver, nil
	}

	log.Debugf("parsing squashfs file: %s", s.squashfsPath)

	f, err := os.Open(s.squashfsPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open squashfs file: %w", err)
	}

	s.squashFileCloser = func() error {
		if err := f.Close(); err != nil {
			return fmt.Errorf("unable to close squashfs file: %w", err)
		}
		return nil
	}

	fileMeta, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("unable to stat squashfs file: %w", err)
	}

	size := fileMeta.Size()

	fileCatalog := image.NewFileCatalog()

	prog := bus.StartIndexingFiles(filepath.Base(s.squashfsPath))

	b := diskFile.New(f, true)
	fs, err := squashfs.Read(b, fileMeta.Size(), 0, 0)
	if err != nil {
		err := fmt.Errorf("unable to open squashfs file: %w", err)
		prog.SetError(err)
		return nil, err
	}

	tree := filetree.New()
	if err := intFile.WalkDiskDir(fs, "/", squashfsVisitor(tree, fileCatalog, &size, prog)); err != nil {
		err := fmt.Errorf("failed to walk squashfs file=%q: %w", s.squashfsPath, err)
		prog.SetError(err)
		return nil, err
	}

	prog.SetCompleted()

	s.resolver = &fileresolver.FiletreeResolver{
		Chroot:        fileresolver.ChrootContext{},
		Tree:          tree,
		Index:         fileCatalog.Index,
		SearchContext: filetree.NewSearchContext(tree, fileCatalog.Index),
		Opener: func(ref stereoFile.Reference) (io.ReadCloser, error) {
			return fileCatalog.Open(ref)
		},
	}

	s.fs = fs

	return s.resolver, nil
}

type linker interface {
	Readlink() (string, error)
}

func squashfsVisitor(ft filetree.Writer, fileCatalog *image.FileCatalog, size *int64, prog *monitor.TaskProgress) intFile.WalkDiskDirFunc {
	builder := filetree.NewBuilder(ft, fileCatalog.Index)

	return func(fsys filesystem.FileSystem, path string, d os.FileInfo, walkErr error) error {
		if walkErr != nil {
			log.WithFields("error", walkErr, "path", path).Trace("unable to walk squash file path")
			return walkErr
		}

		prog.AtomicStage.Set(path)

		var f filesystem.File
		var mimeType string
		var err error

		if !d.IsDir() {
			f, err = fsys.OpenFile(intFile.ToFSPath(path), os.O_RDONLY)
			if err != nil {
				log.WithFields("error", err, "path", path).Trace("unable to open squash file path")
			} else {
				defer f.Close()
				mimeType = stereoFile.MIMEType(f)
			}
		}

		var ty stereoFile.Type
		var linkPath string
		switch {
		case d.IsDir():
			// in some implementations, the mode does not indicate a directory, so we check the FileInfo type explicitly
			ty = stereoFile.TypeDirectory
		default:
			ty = stereoFile.TypeFromMode(d.Mode())
			if ty == stereoFile.TypeSymLink && f != nil {
				if l, ok := f.(linker); ok {
					linkPath, _ = l.Readlink()
				}
			}
		}

		metadata := stereoFile.Metadata{
			FileInfo:        d,
			Path:            path,
			LinkDestination: linkPath,
			Type:            ty,
			MIMEType:        mimeType,
		}

		fileReference, err := builder.Add(metadata)
		if err != nil {
			return err
		}

		if fileReference == nil {
			return nil
		}

		if size != nil {
			*(size) += metadata.Size()
		}
		fileCatalog.AssociateOpener(*fileReference, func() (io.ReadCloser, error) {
			return fsys.OpenFile(intFile.ToFSPath(path), os.O_RDONLY)
		})

		prog.Increment()
		return nil
	}
}

func isSquashFSFile(mimeType, path string) bool {
	if mimeType == "application/vnd.squashfs" || mimeType == "application/x-squashfs" {
		return true
	}

	ext := filepath.Ext(path)
	return ext == ".snap" || ext == ".squashfs"
}

func deriveID(path, name, version string, digests []file.Digest) artifact.ID {
	var xxhDigest string
	for _, d := range digests {
		if strings.ToLower(strings.ReplaceAll(d.Algorithm, "-", "")) == "xxh64" {
			xxhDigest = d.Value
			break
		}
	}

	if xxhDigest == "" {
		xxhDigest = digestOfFileContents(path)
	}

	info := fmt.Sprintf("%s:%s@%s", xxhDigest, name, version)
	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(info).String())
}

// return the xxhash64 of the file contents, or the xxhash64 of the path if the file cannot be read
func digestOfFileContents(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return digestOfReader(strings.NewReader(path))
	}
	defer f.Close()
	return digestOfReader(f)
}

func digestOfReader(r io.Reader) string {
	hasher := xxhash.New64()
	_, _ = io.Copy(hasher, r)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
