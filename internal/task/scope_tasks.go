package task

import (
	"context"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

func NewScopesTask() Task {
	fn := func(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		finalizeScope(builder)
		return nil
	}

	return NewTask("scope-cataloger", fn)
}

func finalizeScope(builder sbomsync.Builder) {
	accessor := builder.(sbomsync.Accessor)

	// remove all packages that doesn't exist in the final state of the image
	packagesToDelete := packagesToRemove(accessor)
	builder.DeletePackages(packagesToDelete...)
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
	for p := range s.Artifacts.Packages.Enumerate() {
		toDelete := true
		for _, l := range p.Locations.ToSlice() {
			if l.IsSquashedLayer {
				toDelete = false
				break
			}
		}
		if toDelete {
			pkgsToDelete = append(pkgsToDelete, p.ID())
		}
	}
	return pkgsToDelete
}
