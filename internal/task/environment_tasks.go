package task

import (
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
)

// TODO: add tui element here?

func NewEnvironmentTask() Task {
	fn := func(resolver file.Resolver, builder sbomsync.Builder) error {
		release := linux.IdentifyRelease(resolver)
		if release != nil {
			builder.SetLinuxDistribution(*release)
		}

		return nil
	}

	return NewTask("environment-cataloger", fn)
}
