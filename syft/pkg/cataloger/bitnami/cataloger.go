/*
Package bitnami provides a concrete Cataloger implementation for capturing packages embedded within Bitnami SBOM files.
*/
package bitnami

import (
	"context"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "bitnami-cataloger"

// NewCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseSBOM,
			"/opt/bitnami/**/.spdx-*.spdx",
		)
}

func parseSBOM(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	s, sFormat, _, err := format.Decode(reader)
	if err != nil {
		return nil, nil, err
	}

	if s == nil {
		log.WithFields("path", reader.Location.RealPath).Trace("file is not an SBOM")
		return nil, nil, nil
	}

	// Bitnami exclusively uses SPDX JSON SBOMs
	if sFormat != "spdx-json" {
		log.WithFields("path", reader.Location.RealPath).Trace("file is not an SPDX JSON SBOM")
		return nil, nil, nil
	}

	var newPkgToFileRelationship = func(p pkg.Package) artifact.Relationship {
		return artifact.Relationship{
			From: p,
			To:   reader.Location.Coordinates,
			Type: artifact.DescribedByRelationship,
		}
	}

	var pkgs []pkg.Package
	relationships := s.Relationships
	for _, p := range s.Artifacts.Packages.Sorted() {
		// replace all locations on the package with the location of the SBOM file.
		// Why not keep the original list of locations? Since the "locations" field is meant to capture
		// where there is evidence of this file, and the catalogers have not run against any file other than,
		// the SBOM, this is the only location that is relevant for this cataloger.
		p.Locations = file.NewLocationSet(
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		p.FoundBy = catalogerName
		if strings.HasPrefix(p.PURL, "pkg:bitnami") {
			p.Type = pkg.BitnamiPkg
			metadata, err := parseBitnamiPURL(p.PURL)
			if err != nil {
				return nil, nil, err
			}

			p.Metadata = metadata
		}
		// TODO: what to do with non-bitnami packages included in Bitnami SBOMs?
		// How do we manage duplicates if packages are reported by N (N>1) catalogers
		// (e.g. a Golang package is both reported by Bitnami & Golang catalogers)?
		pkgs = append(pkgs, p)
		// TODO: should we do this for every package in the SBOM or only for the SBOM
		// main application?
		relationships = append(relationships, newPkgToFileRelationship(p))
	}

	return pkgs, relationships, nil
}
