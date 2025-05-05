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

func NewDeepSquashedScopeCleanupTask() Task {
	fn := func(_ context.Context, _ file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		// remove all packages that doesn't exist in the final state of the image
		builder.DeletePackages(packagesToRemove(accessor)...)
		return nil
	}

	return NewTask("deep-squashed-cleaner", fn)
}

func packagesToRemove(accessor sbomsync.Accessor) []artifact.ID {
	pkgsToDelete := make([]artifact.ID, 0)
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		filterDuplicates := make(map[string]bool)
		for p := range s.Artifacts.Packages.Enumerate() {
			noSquashed := true
			noPrimary := true
			for _, l := range p.Locations.ToSlice() {
				isPrimaryEvidence := l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation
				switch l.Annotations[file.VisibleAnnotationKey] {
				case file.VisibleAnnotation:
					if isPrimaryEvidence || p.Type == pkg.BinaryPkg {
						noSquashed = false
						break
					}
				case "":
					if isPrimaryEvidence {
						if exists := filterDuplicates[getKey(p, l)]; exists {
							break
						}
						filterDuplicates[getKey(p, l)] = true
						noPrimary = false
						break
					}
				}
			}

			if noSquashed && noPrimary {
				pkgsToDelete = append(pkgsToDelete, p.ID())
			}
		}
	})
	return pkgsToDelete
}

func getKey(pkg pkg.Package, loc file.Location) string {
	return fmt.Sprintf("%s-%s-%s-%s", pkg.Name, pkg.Version, loc.RealPath, loc.AccessPath)
}
