package utils

import (
	"fmt"
	"io"

	"golang.org/x/xerrors"
)

const (
	BlockSize  = 4096
	SectorSize = 512
)

type SectorReader interface {
	ReadSector(r io.Reader) ([]byte, error)
}

func DefaultSectorReader() *sectorReader {
	return &sectorReader{
		sectorSize: SectorSize,
	}
}

var allowedSectorSize = []int{512, 4096}

func NewSectorReader(sectorSize int) (*sectorReader, error) {
	validSectorSize := false
	for _, s := range allowedSectorSize {
		if s == sectorSize {
			validSectorSize = true
			break
		}
	}
	if !validSectorSize {
		return nil, fmt.Errorf("failed to instantiate chunk reader, invalid sector size: %d", sectorSize)
	}

	return &sectorReader{
		sectorSize: sectorSize,
	}, nil
}

type sectorReader struct {
	sectorSize int
}

func (c sectorReader) ReadSector(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, c.sectorSize)
	for i := 0; i < c.sectorSize/SectorSize; i++ {
		b, err := readSector(r)
		if err != nil {
			return nil, xerrors.Errorf("failed to read sector: %w", err)
		}

		buf = append(buf, b...)
	}

	if len(buf) != c.sectorSize {
		return nil, fmt.Errorf("sector size error, expected(%d), actual(%d)", c.sectorSize, len(buf))
	}

	return buf, nil
}

func ReadBlock(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, BlockSize)
	for i := 0; i < BlockSize/SectorSize; i++ {
		b, err := readSector(r)
		if err != nil {
			return nil, xerrors.Errorf("failed to read block: %w", err)
		}

		buf = append(buf, b...)
	}

	if len(buf) != BlockSize {
		return nil, fmt.Errorf("block size error, expected(%d), actual(%d)", BlockSize, len(buf))
	}

	return buf, nil
}

func readSector(r io.Reader) ([]byte, error) {
	buf := make([]byte, SectorSize)
	i, err := r.Read(buf)
	if err != nil {
		return nil, xerrors.Errorf("failed to read: %w", err)
	}
	if i != SectorSize {
		return nil, xerrors.Errorf("read size error, expected(%d), actual(%d)", SectorSize, i)
	}

	return buf, nil
}
