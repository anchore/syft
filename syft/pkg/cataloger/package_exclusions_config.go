package cataloger

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg/cataloger/alpm"
	"github.com/anchore/syft/syft/pkg/cataloger/apkdb"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
)

type CatalogerType string

const (
	OsCatalogerType     CatalogerType = "os"
	BinaryCatalogerType CatalogerType = "binary"
)

var CatalogerTypeIndex = map[CatalogerType][]string{
	"os": []string{
		apkdb.CatalogerName,
		alpm.CatalogerName,
	},
	"binary": []string{
		binary.CatalogerName,
	},
}

type PackageExclusionsConfig struct {
	Exclusions []PackageExclusion
}

type PackageExclusion struct {
	RelationshipType artifact.RelationshipType
	ParentType       CatalogerType
	ExclusionType    CatalogerType
}

func DefaultPackageExclusionsConfig() PackageExclusionsConfig {
	return PackageExclusionsConfig{
		Exclusions: []PackageExclusion{
			{
				RelationshipType: artifact.OwnershipByFileOverlapRelationship,
				ParentType:       OsCatalogerType,
				ExclusionType:    BinaryCatalogerType,
			},
		},
	}
}
