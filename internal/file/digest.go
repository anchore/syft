package file

import (
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/xerrors"

	"github.com/anchore/syft/internal/log"
)

const DefaultDigestAlgorithm = "sha1"

// Digest takes a filepath and returns a sha1 digest for the given contents
func Digest(filepath string) (digest string, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return digest, xerrors.Errorf("unable to open file: %s - %w", filepath, err)
	}

	h := sha1.New() //nolint:gosec
	if _, err := io.Copy(h, file); err != nil {
		return digest, xerrors.Errorf("unable to calculate SHA-1 for %s: %w", filepath, err)
	}

	defer func() {
		err := file.Close()
		if err != nil {
			log.Errorf("unable to close source file=%q from zip=%q: %+v", file.Name, filepath, err)
		}
	}()
	return hex.EncodeToString(h.Sum(nil)), nil
}
