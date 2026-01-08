package bundle

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"

	"github.com/anchore/syft/syft/internal/unionreader"
)

// ExtractDepsJSONFromELFBundle extracts the deps.json content from a .net singlefile
// bundle contained within an ELF bin
func ExtractDepsJSONFromELFBundle(r unionreader.UnionReader) (string, error) {
	headerOffset, err := findBundleHeaderOffsetInELF(r)
	if err != nil || headerOffset == 0 {
		return "", err
	}
	return ReadDepsJSONFromBundleHeader(r, headerOffset)
}

func findBundleHeaderOffsetInELF(r unionreader.UnionReader) (int64, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return 0, nil
	}

	elfEndOffset := calculateELFEndOffset(elfFile)
	if elfEndOffset == 0 {
		return 0, nil
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	searchData := make([]byte, elfEndOffset)
	n, err := io.ReadFull(r, searchData)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, err
	}
	searchData = searchData[:n]

	idx := bytes.Index(searchData, dotNetBundleSignature)
	if idx == -1 || idx < 8 {
		return 0, nil
	}

	return int64(binary.LittleEndian.Uint64(searchData[idx-8 : idx])), nil
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
