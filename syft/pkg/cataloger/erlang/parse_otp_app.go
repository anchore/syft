package erlang

import (
	"context"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseOTPApp parses a OTP *.app files to a package objects
func parseOTPApp(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	doc, err := parseErlang(reader)
	if err != nil {
		// there are multiple file formats that use the *.app extension, so it's possible that this is not an OTP app file at all
		// ... which means we should not return an error here
		log.WithFields("error", err).Trace("unable to parse Erlang OTP app")
		return nil, nil, nil
	}

	var packages []pkg.Package

	root := doc.Get(0)

	name := root.Get(1).String()

	keys := root.Get(2)

	for _, key := range keys.Slice() {
		if key.Get(0).String() == "vsn" {
			version := key.Get(1).String()

			p := newPackageFromOTP(
				name, version,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			)

			packages = append(packages, p)
		}
	}

	return packages, nil, nil
}

// integrity check
var _ generic.Parser = parseOTPApp
