package ocaml

import (
	"context"
	"fmt"
	"path"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// parseOpamSwitchState catalogs the packages installed in an opam switch. The switch-state file at
// `<switch>/.opam-switch/switch-state` lists them; opam keeps the opam file of each, with its license, source and
// dependencies, at `<switch>/.opam-switch/packages/<name>.<version>/opam`. Relationships are resolved within the
// switch only, so that packages of other switches are never linked.
func parseOpamSwitchState(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	data, err := readMetadataFile(reader)
	if err != nil {
		return nil, nil, err
	}
	installed, err := parseSwitchState(data)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse opam switch state: %w", err)
	}

	switchDir := path.Dir(reader.Path())
	// a copy: WithAnnotation writes to the annotations of the location it is called on
	stateLocation := reader.WithoutAnnotations().WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)
	var pkgs []pkg.Package
	for _, nameVersion := range installed {
		name, version, ok := splitNameVersion(nameVersion)
		if !ok {
			log.WithFields("package", nameVersion, "path", reader.Path()).Trace("unexpected package in opam switch state")
			continue
		}
		fields, opamLocation, found := readSiblingOpamFields(resolver, path.Join(switchDir, "packages", nameVersion, opamFileName))
		if !found {
			// the switch state is enough to know that the package is installed
			pkgs = append(pkgs, newOpamPackage(ctx, opamMetadata(name, version, opamFields{}), reader.Location))
			continue
		}
		p := newOpamPackage(ctx, opamMetadata(name, version, fields), opamLocation)
		p.Locations.Add(stateLocation)
		p.SetID()
		pkgs = append(pkgs, p)
	}
	return pkgs, dependency.Resolve(opamDependencySpecifier, pkgs), nil
}
