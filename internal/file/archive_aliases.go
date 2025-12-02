package file

import (
	"context"
	"io"
	"os"
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
func IdentifyArchive(ctx context.Context, path string) (archives.Format, io.Reader, error) {
	// First, try to identify using the alias-mapped path (filename-based detection)
	normalizedPath := handleCompoundArchiveAliases(path)
	format, outReader, err := archives.Identify(ctx, normalizedPath, nil)
	if err == nil && format != nil {
		return format, outReader, nil
	}

	// If filename-based detection failed,
	// try opening the file for content-based detection
	f, openErr := os.Open(path)
	if openErr != nil {
		// Return the original error from archives.Identify
		return format, outReader, err
	}
	defer f.Close()

	return archives.Identify(ctx, path, f)
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
