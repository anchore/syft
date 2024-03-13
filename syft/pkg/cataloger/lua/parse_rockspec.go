package lua

import (
	"context"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type luaRockPackage struct {
	Name         string
	Version      string
	License      string
	Homepage     string
	Description  string
	Dependencies map[string]string
	Repository   repository
}

type repository struct {
	URL string
}

// parseRockspec parses a package.rockspec and returns the discovered Lua packages.
func parseRockspec(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	doc, err := parseRockspecData(reader)
	if err != nil {
		log.WithFields("error", err).Trace("unable to parse Rockspec app")
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	var name, version, license, homepage, description, url string

	for _, node := range doc.value {
		switch node.key {
		case "package":
			name = node.value.(string)
		case "version":
			version = node.value.(string)
		case "source":
			for _, child := range node.value.([]rockspecNode) {
				if child.key == "url" {
					url = child.value.(string)
					break
				}
			}
		case "description":
			for _, child := range node.value.([]rockspecNode) {
				switch child.key {
				case "summary":
					description = child.value.(string)
				case "homepage":
					homepage = child.value.(string)
				case "license":
					license = strings.ReplaceAll(child.value.(string), " ", "-")
				}
			}
		}
	}

	p := newPackageLuaRockPackage(
		luaRockPackage{
			Name:    name,
			Version: version,
			License: license,
			Repository: repository{
				URL: url,
			},
			Homepage:    homepage,
			Description: description,
		},
		reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	pkgs = append(pkgs, p)

	return pkgs, nil, nil
}
