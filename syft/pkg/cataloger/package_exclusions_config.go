package cataloger

import (
	"golang.org/x/exp/slices"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/alpm"
	"github.com/anchore/syft/syft/pkg/cataloger/apkdb"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
)

type CategoryType string

const (
	OsCatalogerType     CategoryType = "os"
	BinaryCatalogerType CategoryType = "binary"
)

var CatalogerTypeIndex = map[CategoryType][]string{
	"os": {
		apkdb.CatalogerName,
		alpm.CatalogerName,
	},
	"binary": {
		binary.CatalogerName,
	},
}

type PackageExclusionsConfig struct {
	Exclusions []PackageExclusion
}

type PackageExclusion struct {
	RelationshipType artifact.RelationshipType
	ParentType       CategoryType
	ExclusionType    CategoryType
}

func (e PackageExclusion) Match(r artifact.Relationship, c *pkg.Collection) bool {
	parent := c.Package(r.From.ID())
	if parent == nil {
		return false
	}
	child := c.Package(r.To.ID())
	if child == nil {
		return false
	}

	parentInExclusion := slices.Contains(CatalogerTypeIndex[e.ParentType], parent.FoundBy)
	childInExclusion := slices.Contains(CatalogerTypeIndex[e.ExclusionType], child.FoundBy)

	return e.RelationshipType == r.Type && parentInExclusion && childInExclusion
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
