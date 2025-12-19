package file

import (
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/mholt/archives"
)

// compoundExtensionAliases maps shorthand archive extensions to their full forms.
// The mholt/archives library doesn't recognize these aliases natively.
//
// See: https://github.com/anchore/syft/issues/4416
// Reference: https://github.com/mholt/archives?tab=readme-ov-file#supported-compression-formats
var compoundExtensionAliases = map[string]string{
	".tgz":  ".tar.gz",
	".tbz2": ".tar.bz2",
	".txz":  ".tar.xz",
	".tlz":  ".tar.lz",
	".tzst": ".tar.zst",
}

// IdentifyArchive is a wrapper around archives.Identify that handles compound extension
// aliases (like .tgz -> .tar.gz) transparently. It first attempts filename-based detection
// using the alias map, and falls back to content-based detection if needed.
//
// This function is a drop-in replacement for archives.Identify that centralizes
// the compound alias handling logic in one place.
func IdentifyArchive(ctx context.Context, path string, r io.Reader) (archives.Format, io.Reader, error) {
	// First, try to identify using the alias-mapped path (filename-based detection)
	normalizedPath := handleCompoundArchiveAliases(path)
	return archives.Identify(ctx, normalizedPath, r)
}

// handleCompoundArchiveAliases normalizes archive file paths that use compound extension
// aliases (like .tgz) to their full forms (like .tar.gz) for correct identification
// by the mholt/archives library.
func handleCompoundArchiveAliases(path string) string {
	ext := filepath.Ext(path)
	if newExt, ok := compoundExtensionAliases[ext]; ok {
		return strings.TrimSuffix(path, ext) + newExt
	}
	return path
}
