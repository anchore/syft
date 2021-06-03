package file

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// directoryEndLen, readByf, directoryEnd, and findSignatureInBlock were copied from the golang stdlib, specifically:
// - https://github.com/golang/go/blob/go1.16.4/src/archive/zip/struct.go
// - https://github.com/golang/go/blob/go1.16.4/src/archive/zip/reader.go
// findArchiveStartOffset is derived from the same stdlib utils, specifically the readDirectoryEnd function.

const directoryEndLen = 22

// ZipReadCloser is a drop-in replacement for zip.ReadCloser (from zip.OpenReader) that additionally considers zips
// that have bytes prefixed to the front of the archive (common with self-extracting jars).
type ZipReadCloser struct {
	*zip.Reader
	io.Closer
}

// OpenZip provides a ZipReadCloser for the given filepath.
func OpenZip(filepath string) (*ZipReadCloser, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	// some archives may have bytes prepended to the front of the archive, such as with self executing JARs. We first
	// need to find the start of the archive and keep track of this offset.
	offset, err := findArchiveStartOffset(f, fi.Size())
	if err != nil {
		return nil, fmt.Errorf("cannot find beginning of zip archive=%q : %w", filepath, err)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to beginning of archive: %w", err)
	}

	size := fi.Size() - int64(offset)

	r, err := zip.NewReader(io.NewSectionReader(f, int64(offset), size), size)
	if err != nil {
		return nil, fmt.Errorf("unable to open ZipReadCloser @ %q: %w", filepath, err)
	}

	return &ZipReadCloser{
		Reader: r,
		Closer: f,
	}, nil
}

type readBuf []byte

func (b *readBuf) uint16() uint16 {
	v := binary.LittleEndian.Uint16(*b)
	*b = (*b)[2:]
	return v
}

func (b *readBuf) uint32() uint32 {
	v := binary.LittleEndian.Uint32(*b)
	*b = (*b)[4:]
	return v
}

type directoryEnd struct {
	diskNbr            uint32 // unused
	dirDiskNbr         uint32 // unused
	dirRecordsThisDisk uint64 // unused
	directoryRecords   uint64
	directorySize      uint64
	directoryOffset    uint64 // relative to file
}

// note: this is derived from readDirectoryEnd within the archive/zip package
func findArchiveStartOffset(r io.ReaderAt, size int64) (startOfArchive uint64, err error) {
	// look for directoryEndSignature in the last 1k, then in the last 65k
	var buf []byte
	var directoryEndOffset int64
	for i, bLen := range []int64{1024, 65 * 1024} {
		if bLen > size {
			bLen = size
		}
		buf = make([]byte, int(bLen))
		if _, err := r.ReadAt(buf, size-bLen); err != nil && err != io.EOF {
			return 0, err
		}
		if p := findSignatureInBlock(buf); p >= 0 {
			buf = buf[p:]
			directoryEndOffset = size - bLen + int64(p)
			break
		}
		if i == 1 || bLen == size {
			return 0, zip.ErrFormat
		}
	}

	if buf == nil {
		// we were unable to find the directoryEndSignature block
		return 0, zip.ErrFormat
	}

	// read header into struct
	b := readBuf(buf[4:]) // skip signature
	d := &directoryEnd{
		diskNbr:            uint32(b.uint16()),
		dirDiskNbr:         uint32(b.uint16()),
		dirRecordsThisDisk: uint64(b.uint16()),
		directoryRecords:   uint64(b.uint16()),
		directorySize:      uint64(b.uint32()),
		directoryOffset:    uint64(b.uint32()),
	}
	// Calculate where the zip data actually begins
	startOfArchive = uint64(directoryEndOffset) - d.directorySize - d.directoryOffset

	// These values mean that the file can be a zip64 file
	if d.directoryRecords == 0xffff || d.directorySize == 0xffff || d.directoryOffset == 0xffffffff {
		startOfArchive = 0 // Prefixed data not supported
	}

	// Make sure directoryOffset points to somewhere in our file.
	if o := int64(d.directoryOffset); o < 0 || o >= size {
		return 0, zip.ErrFormat
	}
	return startOfArchive, nil
}

func findSignatureInBlock(b []byte) int {
	for i := len(b) - directoryEndLen; i >= 0; i-- {
		// defined from directoryEndSignature
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 0x05 && b[i+3] == 0x06 {
			// n is length of comment
			n := int(b[i+directoryEndLen-2]) | int(b[i+directoryEndLen-1])<<8
			if n+directoryEndLen+i <= len(b) {
				return i
			}
		}
	}
	return -1
}
