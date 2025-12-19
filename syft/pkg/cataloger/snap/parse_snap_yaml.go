package snap

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseSnapYaml parses meta/snap.yaml files. This file contains metadata about
// the snap container itself (name, version, base, etc.), not about packages
// inside the snap. We don't create a package entry for the snap container -
// the actual contents (binaries, debs) are cataloged by their respective
// catalogers (binary cataloger for binaries built from source, and other snap
// parsers like parse_system_manifest.go for debian packages from primed-stage-packages).
func parseSnapYaml(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
