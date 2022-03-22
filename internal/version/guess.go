package version

import (
	"runtime/debug"
	"strings"

	"github.com/anchore/syft/internal/log"
)

func Guess() string {
	v := FromBuild().Version
	if strings.HasPrefix(v, "v") {
		return v
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Warn("syft version could not be determined: unable to find the buildinfo section of the binary")
		return v
	}

	var found bool
	for _, d := range buildInfo.Deps {
		if d.Path == "github.com/anchore/syft" {
			v = d.Version
			found = true
			break
		}
	}

	if !found {
		// look for probable forks
		for _, d := range buildInfo.Deps {
			if strings.HasSuffix(d.Path, "/syft") {
				v = d.Version
				found = true
				break
			}
		}
	}

	if !found {
		log.Warn("syft version could not be determined: unable to find syft within the buildinfo section of the binary")
	}

	return v
}
