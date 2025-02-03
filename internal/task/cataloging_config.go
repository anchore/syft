package task

import (
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
)

type CatalogingFactoryConfig struct {
	ComplianceConfig     cataloging.ComplianceConfig
	SearchConfig         cataloging.SearchConfig
	RelationshipsConfig  cataloging.RelationshipsConfig
	DataGenerationConfig cataloging.DataGenerationConfig
	PackagesConfig       pkgcataloging.Config
	FilesConfig          filecataloging.Config
}

func DefaultCatalogingFactoryConfig() CatalogingFactoryConfig {
	return CatalogingFactoryConfig{
		ComplianceConfig:     cataloging.DefaultComplianceConfig(),
		SearchConfig:         cataloging.DefaultSearchConfig(),
		RelationshipsConfig:  cataloging.DefaultRelationshipsConfig(),
		DataGenerationConfig: cataloging.DefaultDataGenerationConfig(),
		PackagesConfig:       pkgcataloging.DefaultConfig(),
		FilesConfig:          filecataloging.DefaultConfig(),
	}
}
