package task

import (
	"context"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
)

// TODO: add tui element here?

func NewEnvironmentTask() Task {
	fn := func(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		release := linux.IdentifyRelease(resolver)
		if release != nil {
			builder.SetLinuxDistribution(*release)
		}

		return nil
	}

	return NewTask("environment-cataloger", fn)
}
