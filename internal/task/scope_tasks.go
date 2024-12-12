package task

import (
	"context"
	"fmt"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func NewScopesTask() Task {
	fn := func(_ context.Context, _ file.Resolver, builder sbomsync.Builder) error {
		finalizeScope(builder)
		return nil
	}

	return NewTask("scope-cataloger", fn)
}

func finalizeScope(builder sbomsync.Builder) {
	accessor := builder.(sbomsync.Accessor)

	// remove all packages that doesn't exist in the final state of the image
	builder.DeletePackages(packagesToRemove(accessor)...)
}

func packagesToRemove(accessor sbomsync.Accessor) []artifact.ID {
	pkgsToDelete := make([]artifact.ID, 0)
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		// remove packages which doesn't exist in the final state of the image
		pkgsToDelete = append(pkgsToDelete, getPackagesToDelete(s)...)
	})
	return pkgsToDelete
}

func getPackagesToDelete(s *sbom.SBOM) []artifact.ID {
	pkgsToDelete := make([]artifact.ID, 0)
	filterDuplicates := make(map[string]bool)
	for p := range s.Artifacts.Packages.Enumerate() {
		noSquashed := true
		noPrimary := true
		for _, l := range p.Locations.ToSlice() {
			if exists := filterDuplicates[getKey(p, l)]; exists {
				break
			}
			filterDuplicates[getKey(p, l)] = true
			scope := l.LocationMetadata.Annotations[file.ScopeAnnotationKey]
			evidence := l.LocationMetadata.Annotations[pkg.EvidenceAnnotationKey]
			if scope == file.SquashedScopeAnnotation && evidence == pkg.PrimaryEvidenceAnnotation {
				noSquashed = false
				break
			}
			if scope == "" && evidence == pkg.PrimaryEvidenceAnnotation {
				noPrimary = false
				break
			}
		}

		if noSquashed && noPrimary {
			pkgsToDelete = append(pkgsToDelete, p.ID())
		}
	}
	return pkgsToDelete
}

func getKey(pkg pkg.Package, loc file.Location) string {
	return fmt.Sprintf("%s-%s-%s-%s", pkg.Name, pkg.Version, loc.RealPath, loc.AccessPath)
}
