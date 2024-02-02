package task

import (
	"context"

	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

var _ artifact.Identifiable = (*sourceIdentifierAdapter)(nil)

type sourceIdentifierAdapter struct {
	desc source.Description
}

func (s sourceIdentifierAdapter) ID() artifact.ID {
	return artifact.ID(s.desc.ID)
}

func NewRelationshipsTask(cfg cataloging.RelationshipsConfig, src source.Description) Task {
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		relationship.Finalize(
			builder,
			cfg,
			&sourceIdentifierAdapter{desc: src})

		return nil
	}

	return NewTask("relationships-cataloger", fn)
}
