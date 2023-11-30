package erlang

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseRebarLock parses a rebar.lock and returns the discovered Elixir packages.
//
//nolint:funlen
func parseOTPApp(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	doc, err := parseErlang(reader)
	if err != nil {
		return nil, nil, err
	}

	var packages []pkg.Package

	root := doc.Get(0)

	name := root.Get(1).String()

	keys := root.Get(2)

	for _, key := range keys.Slice() {
		if key.Get(0).String() == "vsn" {
			version := key.Get(1).String()

			p := newPackageFromOTP(
				pkg.ErlangOTPApplication{
					Name:    name,
					Version: version,
				},
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			)

			packages = append(packages, p)
		}
	}

	return packages, nil, nil
}

// integrity check
var _ generic.Parser = parseOTPApp
