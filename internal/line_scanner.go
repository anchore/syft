package internal

import (
	"bufio"
	"io"
)

// maxScannedLineSize is the longest line NewLineScanner will return before Scan stops with bufio.ErrTooLong.
// The buffer only grows to this size when a line needs it.
const maxScannedLineSize = 1024 * 1024

// NewLineScanner returns a bufio.Scanner that accepts lines up to 1MB rather than the 64KB default, since
// package metadata files carry long single-line fields (descriptions, license text, dependency lists). Callers
// must still check Err() after scanning.
func NewLineScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(nil, maxScannedLineSize)
	return s
}
