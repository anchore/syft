// in-toto/SBOMit task to enrich package information based on an in-toto attestation.
//
// TODOs (in order of importance):
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

func NewSBOMitTask(cfg CatalogingFactoryConfig) Task {
	fn := func(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		locations, err := resolver.FilesByGlob(attestationGlobs...)
		if err != nil {
			return err
		}

		log.Debugf("sbomit: found %d attestation(s)", len(locations))

		accessor := builder.(sbomsync.Accessor)

		for _, loc := range locations {
			log.Debugf("sbomit: parsing attestation %s", loc.RealPath)
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
			// Current, Attestation -> Action
			// A@X, A@X -> Add an evident-by attestation edge to every existing Node.
			// ---, A@X -> Add a new package entry.
			// A@X, A@Y -> Add a new package entry, leaving the cataloged one untouched.
			// A@X, A@? -> TODO
			for _, p := range result.Packages {
				existing := findPackages(accessor, p)
				// Add a new package if no package with this (name, version, type) exists.
				if len(existing) == 0 {
					addNewPackage(cfg, resolver, builder, loc, p)
					log.Debugf("sbomit:   [+] %s @ %s", p.Name, p.Version)
					continue
				}

				// If (name, version, type) already exists, add agreement relationship to each package node.
				for _, e := range existing {
					addAttestationEvidence(builder, loc, e, p)
					log.Debugf("sbomit:   [~] %s @ %s", e.Name, e.Version)
				}
			}
		}

		return nil
	}

	return NewTask("sbomit", fn)
}

// Return the packages already in the SBOM with the given name, version and type.
func findPackages(accessor sbomsync.Accessor, resolvedPackage resolve.Package) []pkg.Package {
	var matches []pkg.Package

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		for _, p := range s.Artifacts.Packages.PackagesByName(resolvedPackage.Name) {
			if p.Version == resolvedPackage.Version && p.Type == pkg.TypeFromPURL(resolvedPackage.PURL) {
				matches = append(matches, p)
			}
		}
	})

	return matches
}

// Record that the attestation is evidence for a package (whether cataloged or added by SBOMit) through an
// EvidentByRelationship, carrying the attestation's evidence and digests for the package.
func addAttestationEvidence(builder sbomsync.Builder, loc file.Location, target pkg.Package, attested resolve.Package) {
	evidenceData := make([]map[string]any, 0, len(attested.Evidence))
	for _, ev := range attested.Evidence {
		evidenceData = append(evidenceData, map[string]any{
			"source":   string(ev.Source),
			"pkgMgr":   ev.PkgMgr,
			"location": ev.Location, // File path relative to where the attestation ran.
			"artifact": ev.Artifact,
			"digests":  digestData(ev.Digests),
		})
	}

	builder.AddRelationships(artifact.Relationship{
		From: target,
		To:   loc.Coordinates,
		Type: artifact.EvidentByRelationship,
		Data: map[string]any{
			"kind":     "in-toto-attestation",
			"evidence": evidenceData,
		},
	})
}

// Add a package described by an attestation.
func addNewPackage(cfg CatalogingFactoryConfig, resolver file.Resolver, builder sbomsync.Builder, loc file.Location, p resolve.Package) {
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

	// finalize package details (e.g. to add CPEs, license, etc.) just like it's done for regular catalogers' packages.
	pkgs, relationships := finalizePkgCatalogerResults(cfg, resolver, "sbomit", []pkg.Package{syftPkg}, nil)
	syftPkg = pkgs[0]
	builder.AddPackages(syftPkg)
	builder.AddRelationships(relationships...)

	addAttestationEvidence(builder, loc, syftPkg, p)
}

func digestData(digests []resolve.Digest) []map[string]string {
	result := make([]map[string]string, 0, len(digests))
	for _, d := range digests {
		result = append(result, map[string]string{
			"algorithm": d.Algorithm,
			"value":     d.Value,
		})
	}
	return result
}
