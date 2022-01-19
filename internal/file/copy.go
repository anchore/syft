package file

import (
	"errors"
	"fmt"
	"io"
)

const perFileReadLimit = 2 * GB

// safeCopy limits the copy from the reader. This is useful when extracting files from archives to
// protect against decompression bomb attacks.
func safeCopy(writer io.Writer, reader io.Reader) error {
	numBytes, err := io.Copy(writer, io.LimitReader(reader, perFileReadLimit))
	if numBytes >= perFileReadLimit || errors.Is(err, io.EOF) {
		return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
	}
	return nil
}
