// This code was copied from the Go std library.
// https://github.com/golang/go/blob/master/src/cmd/go/internal/version/version.go

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package golang

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	macho "github.com/anchore/go-macholibre"
	"github.com/anchore/syft/internal/log"
)

// isExe reports whether the file should be considered executable.
func isExe(file string, info fs.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return strings.HasSuffix(strings.ToLower(file), ".exe")
	}
	return info.Mode().IsRegular() && info.Mode()&0111 != 0
}

// scanFile scans file to try to report the Go and module versions.
func scanFile(file string, info fs.FileInfo) []*debug.BuildInfo {
	if info.Mode()&fs.ModeSymlink != 0 {
		// Accept file symlinks only.
		i, err := os.Stat(file)
		if err != nil || !i.Mode().IsRegular() {
			log.Debugf("golang version cataloger: %s: symlink", file)
			return nil
		}
		info = i
	}

	if !isExe(file, info) {
		log.Debugf("golang version cataloger: %s: not executable file\n", file)
		return nil
	}

	readers, err := openExe(file)
	if err != nil {
		log.Warnf("golang version cataloger: opening binary: %v", err)
		return nil
	}

	buildInfo := make([]*debug.BuildInfo, 0)
	for _, r := range readers {
		bi, err := buildinfo.Read(r)
		if err != nil {
			if pathErr := (*os.PathError)(nil); !errors.As(err, &pathErr) {
				log.Warnf("golang version cataloger:  %s: %v\n", file, err)
			}
			return nil
		}
		buildInfo = append(buildInfo, bi)
	}
	return buildInfo
}

// openExe opens file and returns it as io.ReaderAt.
func openExe(file string) ([]io.ReaderAt, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 16)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	_, err = f.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	// adding macho multi-architecture support (both for 64bit and 32 bit)... this case is not in the stdlib yet
	if bytes.HasPrefix(data, []byte("\xCA\xFE\xBA\xBE")) || bytes.HasPrefix(data, []byte("\xCA\xFE\xBA\xBF")) {
		var readers []io.ReaderAt
		ers, err := macho.ExtractReaders(f)
		if err != nil {
			return nil, err
		}

		for _, e := range ers {
			readers = append(readers, e.Reader)
		}

		return readers, nil
	}

	return []io.ReaderAt{f}, nil
}
