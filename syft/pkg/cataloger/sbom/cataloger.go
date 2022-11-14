package sbom

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/spdx22json"
	"github.com/anchore/syft/syft/formats/spdx22tagvalue"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "sbom-cataloger"

// NewSBOMCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewSBOMCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(makeParser(syftjson.Format()), "**/*.syft.json").
		WithParserByGlobs(makeParser(cyclonedxjson.Format()), "**/bom.json", "**/*.cdx.json").
		WithParserByGlobs(makeParser(cyclonedxxml.Format()), "**/bom.xml", "**/*.cdx.xml").
		WithParserByGlobs(makeParser(spdx22json.Format()), "**/*.spdx.json").
		WithParserByGlobs(makeParser(spdx22tagvalue.Format()), "**/*.spdx", "**/*.spdx.tv")
}

func makeParser(format sbom.Format) generic.Parser {
	return func(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
		s, err := format.Decode(reader)
		if err != nil {
			return nil, nil, err
		}

		var pkgs []pkg.Package
		var relationships []artifact.Relationship
		for _, p := range s.Artifacts.PackageCatalog.Sorted() {
			// replace all locations on the package with the location of the SBOM file.
			// Why not keep the original list of locations? Since the "locations" field is meant to capture
			// where there is evidence of this file, and the catalogers have not run against any file other than,
			// the SBOM, this is the only location that is relevant for this cataloger.
			p.Locations = source.NewLocationSet(reader.Location)
			p.FoundBy = catalogerName

			pkgs = append(pkgs, p)
			relationships = append(relationships, artifact.Relationship{
				From: p,
				To:   reader.Location.Coordinates,
				Type: artifact.DescribedByRelationship,
			})
		}

		return pkgs, relationships, nil
	}
}
