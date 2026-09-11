package syft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
)

// newArchiveExclusionVisitor builds an index visitor that drops the given patterns from the tree
// rooted at dir, which is one archive's extraction directory. Returns a nil visitor when there is
// nothing to exclude, so the resolver is built exactly as it was before when no pattern applies.
//
// Matching is done against each entry's path RELATIVE to the extraction directory. The directory
// source instead rewrites every pattern to be absolute against the scan root, and reusing that here
// would be wrong twice over: the root would be the wrong one, and an absolute pattern is matched
// against the absolute path of the entry, so a segment of the temp directory holding the extraction
// could satisfy a pattern the archive's own contents never do. Relative matching also keeps the
// patterns intact, which is what lets `**/x` match x at the archive's own root as well as below it.
func newArchiveExclusionVisitor(dir string, patterns []string) (fileresolver.PathIndexVisitor, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	// the indexer reports an absolute, symlink-resolved path to every visitor: the resolver
	// normalizes its root with EvalSymlinks (fileresolver.NormalizeRootDirectory, via the chroot
	// context) and the walk then takes filepath.Abs of it. The prefix to strip has to be derived the
	// same way or it strips nothing - on macOS an extraction directory lives under /var, a symlink
	// to /private/var, and every pattern would quietly match nothing.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve archive extraction directory %q: %w", dir, err)
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("unable to make archive extraction directory %q absolute: %w", dir, err)
	}

	// slash-separated, to match doublestar's syntax on Windows too
	root := filepath.ToSlash(absolute)
	prefix := strings.TrimSuffix(root, "/") + "/"

	return func(_, path string, info os.FileInfo, _ error) error {
		slashed := filepath.ToSlash(path)
		if slashed == root || slashed == prefix {
			// the extraction directory itself is not a candidate: it is the archive, not something in it
			return nil
		}
		relative := strings.TrimPrefix(slashed, prefix)

		for _, pattern := range patterns {
			matches, err := doublestar.Match(pattern, relative)
			if err != nil {
				// a malformed pattern excludes nothing rather than failing the archive; the source
				// rejected anything it does not accept long before the scan reached here
				continue
			}
			if !matches {
				continue
			}
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return fileresolver.ErrSkipPath
		}
		return nil
	}, nil
}

// sourceExclusions returns the exclusion patterns the given source was configured with, or nil when
// it publishes none. Exclusions are the source's own configuration and appear nowhere in
// CreateSBOMConfig, so this is the only way the cataloging side learns them; a source that does not
// implement source.PathExcluder excludes nothing anywhere, archives included.
func sourceExclusions(src source.Source) []string {
	excluder, ok := src.(source.PathExcluder)
	if !ok {
		return nil
	}
	return excluder.ExcludedPaths()
}
