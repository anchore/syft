package relationship

import (
	"slices"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var (
	languageCatalogerTypes = []pkg.Type{
		pkg.PythonPkg,
		pkg.GemPkg,
		pkg.NpmPkg,
		pkg.PhpComposerPkg,
		pkg.PhpPeclPkg,
		pkg.Rpkg,
		pkg.LuaRocksPkg,
		pkg.ErlangOTPPkg,
	}
)

func ExcludeLanguagePackagesByFileOwnershipOverlap(accessor sbomsync.Accessor) {
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		for _, r := range s.Relationships {
			if idToRemove := excludeLanguagePackageByFileOwnershipOverlap(r, s.Artifacts.Packages); idToRemove != "" {
				s.Artifacts.Packages.Delete(idToRemove)
				s.Relationships = RemoveRelationshipsByID(s.Relationships, idToRemove)
			}
		}
	})
}

// excludeLanguagePackageByFileOwnershipOverlap will remove language packages that are owned by OS packages.
// This was implemented as a way to help resolve: https://github.com/anchore/syft/issues/4760
func excludeLanguagePackageByFileOwnershipOverlap(r artifact.Relationship, c *pkg.Collection) artifact.ID {
	if artifact.OwnershipByFileOverlapRelationship != r.Type {
		return ""
	}

	parent := c.Package(r.From.ID())
	if parent == nil {
		return ""
	}

	child := c.Package(r.To.ID())
	if child == nil {
		return ""
	}

	return identifyOverlappingLanguageRelationship(parent, child)
}

// identifyOverlappingLanguageRelationship indicates the package ID to remove if this is an OS pkg -> language pkg relationship.
func identifyOverlappingLanguageRelationship(parent *pkg.Package, child *pkg.Package) artifact.ID {
	if !slices.Contains(osCatalogerTypes, parent.Type) {
		return ""
	}

	if slices.Contains(languageCatalogerTypes, child.Type) {
		return child.ID()
	}

	return ""
}
