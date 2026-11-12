package ai

import (
	"fmt"
	"io"

	"github.com/anchore/syft/internal"
)

// size limits for model companion files and headers. JSON reads that hit a
// limit fail (see readBounded) instead of parsing a truncated document.
// Frontmatter-only reads (README, license) take a prefix instead, since the
// frontmatter sits at the top and is itself capped by maxFrontmatterSize.
const (
	maxHFConfigSize        = 4 * 1024 * 1024
	maxReadmePrefixSize    = 1 * 1024 * 1024 // dir scans; OCI README layers use maxModelFileLayerSize
	maxModelFileLayerSize  = 4 * 1024 * 1024
	maxLicensePrefixSize   = 64 * 1024
	maxModelConfigBlobSize = 1 * 1024 * 1024
	maxFrontmatterSize     = 256 * 1024
	maxFrontmatterValues   = 32
	maxModelNameLength     = 256

	// maxSafeTensorsHeaderSize caps the header JSON (excluding its 8-byte length
	// prefix). It is shared with the OCI source so dir and OCI scans accept the
	// same headers.
	maxSafeTensorsHeaderSize = internal.MaxSafeTensorsHeaderSize
)

// readPrefix reads at most limit bytes. It is for frontmatter-only reads, where
// the rest of the file is never needed.
func readPrefix(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

// readBounded reads at most limit bytes and reports overflow instead of silently truncating.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("content exceeds %d bytes", limit)
	}
	return b, nil
}
