// This code was copied from the Go std library.
// https://github.com/golang/go/blob/master/src/cmd/go/internal/version/version.go

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package golang

import (
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
			log.Debugf("golang cataloger: %s: symlink", file)
			return nil
		}
		info = i
	}

	if !isExe(file, info) {
		log.Debugf("golang cataloger: %s: not executable file\n", file)
		return nil
	}

	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := getReaders(file)
	if err != nil {
		log.Warnf("golang cataloger: opening binary: %v", err)
		return nil
	}

	builds := make([]*debug.BuildInfo, 0)
	for _, r := range readers {
		bi, err := buildinfo.Read(r)
		if err != nil {
			if pathErr := (*os.PathError)(nil); !errors.As(err, &pathErr) {
				log.Warnf("golang cataloger: scanning file %s: %v\n", file, err)
			}
			return nil
		}
		builds = append(builds, bi)
	}

	setArch(readers, builds)

	return builds
}

// openExe opens file and returns it as io.ReaderAt.
func getReaders(file string) ([]io.ReaderAt, error) {
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

	if macho.IsUniversalMachoBinary(f) {
		machoReaders, err := macho.ExtractReaders(f)
		if err != nil {
			log.Debugf("extracting readers: %v", err)
			return nil, err
		}

		var readers []io.ReaderAt
		for _, e := range machoReaders {
			readers = append(readers, e.Reader)
		}

		return readers, nil
	}

	return []io.ReaderAt{f}, nil
}
