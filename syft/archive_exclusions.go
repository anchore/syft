package syft

import (
	"os"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
)

// newArchiveExclusionVisitor builds an index visitor that drops the given patterns from one archive's
// contents, or nil when there is nothing to exclude.
//
// Patterns match against each entry's archive-relative path, unlike the directory source, which
// rewrites patterns absolute against the scan root. An archive is indexed in memory with no host
// location to rewrite against, and matching absolute would let a segment of the scan's temp directory
// satisfy a pattern the contents never do. Relative matching also keeps patterns intact, so `**/x`
// matches x at the archive root as well as below it.
//
// Only `**/`-prefixed patterns reach here (see cataloging.ArchiveExclusionPatterns): those mean the
// same thing at any depth, which is what makes an archive-relative match well defined.
func newArchiveExclusionVisitor(patterns []string) fileresolver.PathIndexVisitor {
	if len(patterns) == 0 {
		return nil
	}

	return func(_, entryPath string, info os.FileInfo, _ error) error {
		for _, pattern := range patterns {
			matches, err := doublestar.Match(pattern, entryPath)
			if err != nil {
				// a malformed pattern excludes nothing rather than failing the archive; the source
				// already validated its patterns
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
	}
}

// sourceExclusions returns the exclusion patterns the source was configured with, or nil. Exclusions
// belong to the source and appear nowhere in CreateSBOMConfig, so this is how the cataloging side
// learns them; a source that is not a source.PathExcluder excludes nothing.
func sourceExclusions(src source.Source) []string {
	excluder, ok := src.(source.PathExcluder)
	if !ok {
		return nil
	}
	return excluder.ExcludedPaths()
}
