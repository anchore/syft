/*
Package sbom provides a concrete Cataloger implementation for capturing packages embedded within SBOM files.
*/
package sbom

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "sbom-cataloger"

// NewCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseSBOM,
			"**/*.syft.json",
			"**/*.bom.*",
			"**/*.bom",
			"**/bom",
			"**/*.sbom.*",
			"**/*.sbom",
			"**/sbom",
			"**/*.cdx.*",
			"**/*.cdx",
			"**/*.spdx.*",
			"**/*.spdx",
		)
}

func parseSBOM(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	readSeeker, err := adaptToReadSeeker(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read SBOM file %q: %w", reader.RealPath, err)
	}
	s, _, _, err := format.Decode(readSeeker)
	if err != nil {
		return nil, nil, err
	}

	if s == nil {
		log.WithFields("path", reader.RealPath).Trace("file is not an SBOM")
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	relationships := s.Relationships
	for _, p := range s.Artifacts.Packages.Sorted() {
		// replace all locations on the package with the location of the SBOM file.
		// Why not keep the original list of locations? Since the "locations" field is meant to capture
		// where there is evidence of this file, and the catalogers have not run against any file other than,
		// the SBOM, this is the only location that is relevant for this cataloger.
		p.Locations = file.NewLocationSet(
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		p.FoundBy = catalogerName

		pkgs = append(pkgs, p)
		relationships = append(relationships, artifact.Relationship{
			From: p,
			To:   reader.Coordinates,
			Type: artifact.DescribedByRelationship,
		})
	}

	return pkgs, relationships, nil
}

func adaptToReadSeeker(reader io.Reader) (io.ReadSeeker, error) {
	// with the stereoscope API and default file.Resolver implementation here in syft, odds are very high that
	// the underlying reader is already a ReadSeeker, so we can just return it as-is. We still want to
	if rs, ok := reader.(io.ReadSeeker); ok {
		return rs, nil
	}

	log.Debug("SBOM cataloger reader is not a ReadSeeker, reading entire SBOM into memory")

	var buff bytes.Buffer
	_, err := io.Copy(&buff, reader)
	return bytes.NewReader(buff.Bytes()), err
}
