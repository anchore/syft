// This code was copied from the Go std library.
// https://github.com/golang/go/blob/master/src/cmd/go/internal/version/version.go

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package golang

import (
	"debug/buildinfo"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	// "cmd/go/internal/base"

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
// If mustPrint is true, scanFile will report any error reading file.
// Otherwise, (mustPrint is false, because scanFile is being called
// by scanDir) scanFile prints nothing for non-Go executables.
func scanFile(file string, info fs.FileInfo) *debug.BuildInfo {
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

	bi, err := buildinfo.ReadFile(file)
	if err != nil {
		if pathErr := (*os.PathError)(nil); !errors.As(err, &pathErr) && filepath.Clean(pathErr.Path) != filepath.Clean(file) {
			log.Warnf("golang version cataloger:  %s: %v\n", file, err)
		}
		return nil
	}

	return bi
}
