package lua

import (
	"context"
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type luaRocksPackage struct {
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
		return nil, nil, fmt.Errorf("unable to parse Rockspec app: %w", err)
	}

	var name, version, license, homepage, description, url string

	for _, node := range doc.value {
		switch node.key {
		case "package":
			name = node.String()
		case "version":
			version = node.String()
		case "source":
			for _, child := range node.Slice() {
				if child.key == "url" {
					url = child.String()
					break
				}
			}
		case "description":
			for _, child := range node.Slice() {
				switch child.key {
				case "summary":
					description = child.String()
				case "homepage":
					homepage = child.String()
				case "license":
					license = strings.ReplaceAll(child.String(), " ", "-")
				}
			}
		}
	}

	p := newLuaRocksPackage(
		luaRocksPackage{
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

	return []pkg.Package{p}, nil, nil
}
