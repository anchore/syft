package java

import (
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

func (p pomXMLCataloger) Catalog(resolver any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}

func NewPomCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	return pomXMLCataloger{cfg: cfg}
}
