package golang

import (
	"debug/buildinfo"
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
		log.Warnf("golang cataloger: failed to open a binary: %v", err)
		return nil, nil
	}

	var builds []*debug.BuildInfo
	for _, r := range readers {
		bi, err := buildinfo.Read(r)

		// note: the stdlib does not export the error we need to check for
		if err != nil {
			if err.Error() == "not a Go executable" {
				// since the cataloger can only select executables and not distinguish if they are a go-compiled
				// binary, we should not show warnings/logs in this case.
				return nil, nil
			}
			// in this case we could not read the or parse the file, but not explicitly because it is not a
			// go-compiled binary (though it still might be).
			// TODO: We should change this back to "warn" eventually.
			//  But right now it's catching too many cases where the reader IS NOT a Go binary at all.
			//  It'd be great to see how we can get those cases to be detected and handled above before we get to
			//  this point in execution.
			log.Infof("golang cataloger: unable to read buildinfo (file=%q): %v", filename, err)
			return nil, nil
		}

		builds = append(builds, bi)
	}

	archs := getArchs(readers, builds)

	return builds, archs
}
