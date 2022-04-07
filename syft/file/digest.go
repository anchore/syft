// nolint:gosec
package file

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/anchore/syft/internal/log"
)

type HashAlgorithm string

const (
	HashAlgoMD5    HashAlgorithm = "MD5"
	HashAlgoSHA1   HashAlgorithm = "SHA-1"
	HashAlgoSHA256 HashAlgorithm = "SHA-256"
)

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func CalculateDigest(filepath string, algorithm HashAlgorithm) (digest *Digest, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return digest, fmt.Errorf("unable to open file: %s - %w", filepath, err)
	}
	var h hash.Hash
	switch algorithm {
	case HashAlgoSHA1:
		h = sha1.New()
	case HashAlgoMD5:
		h = md5.New()
	case HashAlgoSHA256:
		h = sha256.New()
	default:
		return nil, fmt.Errorf("no hash algorithm implemented for %s", algorithm)
	}

	if _, err := io.Copy(h, file); err != nil {
		return digest, fmt.Errorf("unable to calculate %s for %s: %w", algorithm, filepath, err)
	}

	defer func() {
		err := file.Close()
		if err != nil {
			log.Warnf("unable to close source file=%q from zip=%q: %+v", file.Name, filepath, err)
		}
	}()

	return &Digest{
		Algorithm: string(algorithm),
		Value:     hex.EncodeToString(h.Sum(nil)),
	}, nil
}
