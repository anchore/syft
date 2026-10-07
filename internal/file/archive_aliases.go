package file

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/mholt/archives"

	"github.com/anchore/syft/internal/log"
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
func IdentifyArchive(ctx context.Context, path string, r io.Reader) (format archives.Format, reader io.Reader, err error) {
	// archives.Identify sniffs headers from untrusted input and panics rather than
	// returning an error on some malformed files, so a single bad file would otherwise
	// take down the cataloger running over it. Report it as an ordinary identification
	// failure: the caller already handles "this is not an archive".
	defer func() {
		if r := recover(); r != nil {
			log.WithFields("path", path, "panic", r).Debug("recovered from panic while identifying archive")
			log.Tracef("archive identification panic stack:\n%s", debug.Stack())
			format, reader, err = nil, nil, fmt.Errorf("recovered from panic while identifying archive: %v", r)
		}
	}()

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
