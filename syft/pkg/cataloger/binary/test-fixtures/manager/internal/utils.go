package internal

import (
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

func SplitFilepath(path string) []string {
	return strings.Split(path, string(filepath.Separator))
}

func Sha256SumFile(f io.ReadSeeker) (string, error) {
	_, err := f.Seek(0, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("unable to seek to start of file: %w", err)
	}
	hasher := sha256.New()
	_, err = io.Copy(hasher, f)
	if err != nil {
		return "", fmt.Errorf("unable to hash file: %w", err)
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func Sha256SumBytes(buf []byte) string {
	hasher := sha256.New()
	hasher.Write(buf)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
