package file

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
)

func UnGzip(dst string, src string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("unable to open archive (%s): %w", src, err)
	}
	defer func() {
		err = srcFile.Close()
		if err != nil {
			log.Errorf("unable to close archive (%s): %w", src, err)
		}
	}()

	gzr, err := gzip.NewReader(srcFile)
	if err != nil {
		return fmt.Errorf("failed to unzip archive (%s): %w", src, err)
	}
	defer func() {
		err = gzr.Close()
		if err != nil {
			log.Errorf("unable to close gzip reader (%s): %w", gzr, err)
		}
	}()

	target := filepath.Join(dst, strings.TrimSuffix(filepath.Base(src), ".gz"))
	dstFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to create destination file (%s): %w", target, err)
	}
	defer func() {
		err = dstFile.Close()
		if err != nil {
			log.Errorf("unable to close destination file (%s): %w", dstFile, err)
		}
	}()

	if _, err := io.Copy(dstFile, io.LimitReader(gzr, 1*GB)); err != nil {
		return fmt.Errorf("failed to copy file (%s): %w", target, err)
	}
	return nil
}
