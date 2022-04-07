package file

import (
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/internal/log"
)

// Digest takes a filepath and returns a sha1 digest for the given contents
func Digest(filepath string) (digest string, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return digest, fmt.Errorf("unable to open file: %s - %w", filepath, err)
	}

	h := sha1.New() //nolint:gosec
	if _, err := io.Copy(h, file); err != nil {
		return digest, fmt.Errorf("unable to calculate SHA-1 for %s: %w", filepath, err)
	}

	defer func() {
		err := file.Close()
		if err != nil {
			log.Warnf("unable to close source file=%q from zip=%q: %+v", file.Name, filepath, err)
		}
	}()
	return hex.EncodeToString(h.Sum(nil)), nil
}
