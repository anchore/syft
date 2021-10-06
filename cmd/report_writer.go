package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/internal/log"
)

func reportWriter() (io.Writer, func() error, error) {
	nop := func() error { return nil }

	path := strings.TrimSpace(appConfig.File)
	switch len(path) {
	case 0:
		return os.Stdout, nop, nil
	default:
		reportFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, nop, fmt.Errorf("unable to create report file: %w", err)
		}
		return reportFile, func() error {
			log.Infof("report written to file=%q", path)
			return reportFile.Close()
		}, nil
	}
}
