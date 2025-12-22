package java

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const pomCatalogerName = "java-pom-cataloger"

type ArchiveCatalogerConfig struct {
	IncludeArchives bool
}

type pomXMLCataloger struct {
	cfg ArchiveCatalogerConfig
}

func (p pomXMLCataloger) Name() string {
	return pomCatalogerName
}

func (p pomXMLCataloger) Catalog(_ context.Context, _ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}

func NewPomCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	return pomXMLCataloger{cfg: cfg}
}
