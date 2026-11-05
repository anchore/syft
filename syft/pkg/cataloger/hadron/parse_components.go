package hadron

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseComponents

// components is the on-disk format of components.json: a flat map of
// component name to version, e.g. {"openssl": "3.6.3", "curl": "8.21.0"}.
// Hadron has no package manager; this file is the entire installed inventory.
type components map[string]string

func parseComponents(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var comps components
	if err := json.NewDecoder(reader).Decode(&comps); err != nil {
		return nil, nil, fmt.Errorf("failed to decode Hadron components.json: %w", err)
	}

	locations := file.NewLocationSet(reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	var pkgs []pkg.Package
	for name, version := range comps {
		if name == "" || version == "" {
			continue
		}
		p := pkg.Package{
			Name:      name,
			Version:   version,
			PURL:      packageURL(name, version),
			Locations: locations,
			Type:      pkg.HadronPkg,
		}
		p.SetID()
		pkgs = append(pkgs, p)
	}

	// components.json is an unordered JSON object; sort for deterministic output.
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})

	return pkgs, nil, nil
}
