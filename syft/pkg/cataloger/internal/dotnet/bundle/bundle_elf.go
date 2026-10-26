package bundle

import (
	"debug/elf"
	"errors"

	"github.com/anchore/syft/syft/internal/elfutil"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// ExtractDepsJSONFromELFBundle extracts the deps.json content from a .net singlefile
// bundle contained within an ELF bin
func ExtractDepsJSONFromELFBundle(r unionreader.UnionReader) (string, error) {
	elfFile, err := elfutil.NewFile(r)
	if err != nil {
		// a refusal is not the same as "this is not an ELF": elfutil exports this error precisely so the
		// gap it leaves in the SBOM can be reported rather than read as an absence of evidence
		if errors.Is(err, elfutil.ErrDeclaredSizeExceeded) {
			return "", err
		}
		// not an ELF we can parse, so not an ELF bundle
		return "", nil //nolint:nilerr
	}

	return ExtractDepsJSON(r, calculateELFEndOffset(elfFile))
}

func calculateELFEndOffset(f *elf.File) int64 {
	var endOffset int64

	for _, prog := range f.Progs {
		end := int64(prog.Off) + int64(prog.Filesz)
		if end > endOffset {
			endOffset = end
		}
	}

	for _, sec := range f.Sections {
		if sec.Type == elf.SHT_NOBITS {
			continue
		}
		end := int64(sec.Offset) + int64(sec.Size)
		if end > endOffset {
			endOffset = end
		}
	}
	return endOffset + 4096
}
