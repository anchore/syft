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
	if numBytes >= perFileReadLimit {
		return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
	}
	// Propagate decompression / read errors up to the caller. io.Copy
	// on the happy path returns (n, nil); the only way err is non-nil
	// here is that the underlying reader surfaced a real failure
	// ("flate: corrupt input before offset X" on a mangled ZIP entry,
	// a network-backed reader erroring mid-stream, etc.). The previous
	// implementation dropped that error and the caller stored a
	// partial / empty buffer as a "successful" extract, which silently
	// downgraded Java cataloger output and caused SBOM scanners to
	// miss known CVEs (#4806).
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("failed to read archive entry: %w", err)
	}
	return nil
}
