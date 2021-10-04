package golang

import (
	"io"

	"github.com/anchore/syft/syft/pkg"
)

// The build info blob left by the linker is identified by
// a 16-byte header, consisting of buildInfoMagic (14 bytes),
// the binary's pointer size (1 byte),
// and whether the binary is big endian (1 byte).
var buildInfoMagic = []byte("\xff Go buildinf:")

func parseGoBin(path string, reader io.Reader) ([]pkg.Package, error) {
	packages := make(map[string]pkg.Package)
	pkgsSlice := make([]pkg.Package, len(packages))

	// Identify if bin was compiled by go

	// Use go tools to parse packages/mod if go bin

	return pkgsSlice, nil
}
