package file

import (
	"path/filepath"
	"strings"
)

// HandleCompoundArchiveAliases normalizes archive file paths that use compound extension
// aliases (like .tgz) to their full forms (like .tar.gz) for correct identification
// by the mholt/archives library.
//
// See: https://github.com/anchore/syft/issues/4416
// Reference: https://github.com/mholt/archives?tab=readme-ov-file#supported-compression-formats
func HandleCompoundArchiveAliases(path string) string {
	extMap := map[string]string{
		".tgz":  ".tar.gz",
		".tbz2": ".tar.bz2",
		".txz":  ".tar.xz",
		".tlz":  ".tar.lz",
		".tzst": ".tar.zst",
	}

	ext := filepath.Ext(path)
	if newExt, ok := extMap[ext]; ok {
		return strings.TrimSuffix(path, ext) + newExt
	}
	return path
}
