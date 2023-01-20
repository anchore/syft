package golang

import (
	"debug/buildinfo"
	"fmt"
	"io"
	"runtime/debug"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
)

// scanFile scans file to try to report the Go and module versions.
func scanFile(reader unionreader.UnionReader, filename string) ([]*debug.BuildInfo, []string) {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.WithFields("error", err).Warnf("failed to open a golang binary")
		return nil, nil
	}

	var builds []*debug.BuildInfo
	for _, r := range readers {
		bi, err := getBuildInfo(r)
		if err != nil {
			log.WithFields("file", filename, "error", err).Trace("unable to read golang buildinfo")
			continue
		}
		if bi == nil {
			continue
		}
		builds = append(builds, bi)
	}

	archs := getArchs(readers, builds)

	return builds, archs
}

func getBuildInfo(r io.ReaderAt) (bi *debug.BuildInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			// this can happen in cases where a malformed binary is passed in can be initially parsed, but not
			// used without error later down the line. This is the case with :
			// https://github.com/llvm/llvm-project/blob/llvmorg-15.0.6/llvm/test/Object/Inputs/macho-invalid-dysymtab-bad-size
			err = fmt.Errorf("recovered from panic: %v", r)
		}
	}()
	bi, err = buildinfo.Read(r)

	// note: the stdlib does not export the error we need to check for
	if err != nil {
		if err.Error() == "not a Go executable" {
			// since the cataloger can only select executables and not distinguish if they are a go-compiled
			// binary, we should not show warnings/logs in this case. For this reason we nil-out err here.
			err = nil
			return
		}
		// in this case we could not read the or parse the file, but not explicitly because it is not a
		// go-compiled binary (though it still might be).
		return
	}
	return
}
