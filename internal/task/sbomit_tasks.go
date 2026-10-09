// WIP in-toto/SBOMit task to enrich package information based on an in-toto attestation.
//
// TODOs (in order of importance):
// 	- Gating this to be optional instead of running by default.
// 	- Deciding scope of and adding configurations to this Task.
// 	- Adding support for explicit (and possibly out of tree) attestations (e.g. stored on a registry or a specific in-tree attestation)
// 	- Performance testing.

package task

import (
	"context"
	"io"

	"github.com/sbomit/sbomit/pkg/resolve"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var attestationGlobs = []string{
	"**/*.intoto.json",
	"**/*.intoto.jsonl",
	"**/*.attestation.json",
	"**/*.dsse.json",
	"**/*.att",
}

func NewSBOMitTask() Task {
	fn := func(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		locations, err := resolver.FilesByGlob(attestationGlobs...)
		if err != nil {
			return err
		}

		log.Infof("sbomit: found %d attestation(s)", len(locations))

		existingByName := catalogedByName(builder)

		for _, loc := range locations {
			rdr, err := resolver.FileContentsByLocation(loc)
			if err != nil {
				log.WithFields("path", loc.RealPath, "error", err).Warn("sbomit: unable to read attestation")
				continue
			}
			data, err := io.ReadAll(rdr)
			_ = rdr.Close()
			if err != nil {
				log.WithFields("path", loc.RealPath, "error", err).Warn("sbomit: unable to read attestation")
				continue
			}

			result, err := resolve.Resolve(data, resolve.Options{})
			if err != nil {
				log.WithFields("path", loc.RealPath, "error", err).Warn("sbomit: unable to resolve attestation")
				continue
			}

			// Do the simplest cases right now.
			// A@X, A@X -> Add described by attestation to existing Node.
			// ---, A@X -> Add a new package entry.
			// A@X, A@Y -> Update in place.
			for _, p := range result.Packages {
				existing, found := existingByName[p.Name]

				switch {
				case !found:
					addNewPackage(builder, loc, p)
					log.Infof("sbomit:   [A] %s @ %s", p.Name, p.Version)

				case existing.Version == p.Version:
					markAgreement(builder, loc, existing)
					log.Infof("sbomit:   [ ] %s @ %s", p.Name, p.Version)

				default:
					updatePackage(builder, existing, p)
					log.Infof("sbomit:   [M] %s @ %s -> %s", p.Name, existing.Version, p.Version)
				}
			}
		}

		return nil
	}

	return NewTask("sbomit", fn)
}

// Return the already cataloged packages, keyed by name.
func catalogedByName(builder sbomsync.Builder) map[string]pkg.Package {
	byName := map[string]pkg.Package{}

	accessor, ok := builder.(sbomsync.Accessor)
	if !ok {
		return byName
	}

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		for _, p := range s.Artifacts.Packages.Sorted() {
			byName[p.Name] = p
		}
	})

	return byName
}

// Record that the attestation also describes an already cataloged package through a new DescribedByRelationship.
func markAgreement(builder sbomsync.Builder, loc file.Location, existing pkg.Package) {
	builder.AddRelationships(artifact.Relationship{
		From: existing,
		To:   loc.Coordinates,
		Type: artifact.DescribedByRelationship,
	})
}

// Update package info while retaining existing relationships.
func updatePackage(builder sbomsync.Builder, existing pkg.Package, updated resolve.Package) {
	next := existing
	next.Version = updated.Version // Update only the version for now

	builder.DeletePackages(existing.ID())
	builder.AddPackages(next)
}

// Add a package described by an attestation.
func addNewPackage(builder sbomsync.Builder, loc file.Location, p resolve.Package) {
	syftPkg := pkg.Package{
		Name:    p.Name,
		Version: p.Version,
		FoundBy: "sbomit",
		Locations: file.NewLocationSet(
			loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Language: pkg.LanguageFromPURL(p.PURL),
		Type:     pkg.TypeFromPURL(p.PURL),
		PURL:     p.PURL,
	}
	syftPkg.SetID()

	builder.AddPackages(syftPkg)
	builder.AddRelationships(artifact.Relationship{
		From: syftPkg,
		To:   loc.Coordinates,
		Type: artifact.DescribedByRelationship,
	})
}
