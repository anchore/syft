// This code was copied from the Go std library.
// https://github.com/golang/go/blob/master/src/cmd/go/internal/version/version.go

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version implements the ``go version'' command.
package golang

import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	// "cmd/go/internal/base"
)

// a 16-byte header, consisting of buildInfoMagic (14 bytes),
// the binary's pointer size (1 byte),
// and whether the binary is big endian (1 byte).
var buildInfoMagic = []byte("\xff Go buildinf:")

// findVers finds and returns the Go version and module version information
// in the executable x.
func findVers(x exe) (vers, mod string) {
	// Read the first 64kB of text to find the build info blob.
	text := x.DataStart()
	data, err := x.ReadData(text, 64*1024)
	if err != nil {
		return
	}
	for ; !bytes.HasPrefix(data, buildInfoMagic); data = data[32:] {
		if len(data) < 32 {
			return
		}
	}

	// Decode the blob.
	ptrSize := int(data[14])
	bigEndian := data[15] != 0
	var bo binary.ByteOrder
	if bigEndian {
		bo = binary.BigEndian
	} else {
		bo = binary.LittleEndian
	}
	var readPtr func([]byte) uint64
	if ptrSize == 4 {
		readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
	} else {
		readPtr = bo.Uint64
	}
	vers = readString(x, ptrSize, readPtr, readPtr(data[16:]))
	if vers == "" {
		return
	}
	mod = readString(x, ptrSize, readPtr, readPtr(data[16+ptrSize:]))
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		// Strip module framing.
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}
	return vers, mod
}

// readString returns the string at address addr in the executable x.
func readString(x exe, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := x.ReadData(addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := x.ReadData(dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

// isExe reports whether the file should be considered executable.
func isExe(file string, info fs.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return strings.HasSuffix(strings.ToLower(file), ".exe")
	}
	return info.Mode().IsRegular() && info.Mode()&0111 != 0
}

// scanFile scans file to try to report the Go and module versions.
// If mustPrint is true, scanFile will report any error reading file.
// Otherwise (mustPrint is false, because scanFile is being called
// by scanDir) scanFile prints nothing for non-Go executables.
func scanFile(file string, info fs.FileInfo, mustPrint bool) (mod *debug.BuildInfo, goVersion string) {
	if info.Mode()&fs.ModeSymlink != 0 {
		// Accept file symlinks only.
		i, err := os.Stat(file)
		if err != nil || !i.Mode().IsRegular() {
			if mustPrint {
				fmt.Fprintf(os.Stderr, "%s: symlink\n", file)
			}
			return
		}
		info = i
	}

	if !isExe(file, info) {
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: not executable file\n", file)
		}
		return
	}

	bi, err := buildinfo.ReadFile(file)
	if err != nil {
		if mustPrint {
			if pathErr := (*os.PathError)(nil); errors.As(err, &pathErr) && filepath.Clean(pathErr.Path) == filepath.Clean(file) {
				fmt.Fprintf(os.Stderr, "%v\n", file)
			} else {
				fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			}
		}
		return
	}

	fmt.Printf("%s: %s\n", file, bi.GoVersion)
	mod = bi
	goVersion = bi.GoVersion
	return
}
