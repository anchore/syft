package bitnami

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type componentEntry struct {
	Arch    string `json:"arch"`
	Digest  string `json:"digest,omitempty"`
	Distro  string `json:"distro"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

func parseComponentsJSON(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var components map[string]componentEntry

	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&components); err != nil {
		return nil, nil, fmt.Errorf("unable to parse .bitnami_components.json: %w", err)
	}

	var pkgs []pkg.Package

	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry := components[name]

		version, revision := parseVersionRevision(entry.Version)

		var qualifiers []packageurl.Qualifier
		if entry.Arch != "" {
			qualifiers = append(qualifiers, packageurl.Qualifier{Key: "arch", Value: entry.Arch})
		}
		if entry.Distro != "" {
			qualifiers = append(qualifiers, packageurl.Qualifier{Key: "distro", Value: entry.Distro})
		}

		purl := packageurl.NewPackageURL(
			"bitnami",
			"",
			name,
			entry.Version,
			qualifiers,
			"",
		).String()

		metadata := &pkg.BitnamiSBOMEntry{
			Name:         name,
			Version:      version,
			Revision:     revision,
			Architecture: entry.Arch,
			Distro:       entry.Distro,
			Path:         filepath.Join(filepath.Dir(reader.RealPath), name),
		}

		p := pkg.Package{
			Name:    name,
			Version: entry.Version,
			Type:    pkg.BitnamiPkg,
			FoundBy: catalogerName,
			PURL:    purl,
			Locations: file.NewLocationSet(
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
			Metadata: metadata,
		}

		p.SetID()
		pkgs = append(pkgs, p)
	}

	// seems legacy format doesnt have relation between pkgs
	return pkgs, nil, nil
}

func parseVersionRevision(fullVersion string) (version, revision string) {
	lastHyphen := strings.LastIndex(fullVersion, "-")
	if lastHyphen == -1 {
		return fullVersion, ""
	}

	return fullVersion[:lastHyphen], fullVersion[lastHyphen+1:]
}
