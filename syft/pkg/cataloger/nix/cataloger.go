package nix

import (
	"fmt"
	"regexp"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	catalogerName = "nix-store-cataloger"
	nixStoreGlob  = "**/nix/store/*"
)

var (
	numericPattern = regexp.MustCompile(`\d`)
	// attempts to find the right-most example of something that appears to be a version (semver or otherwise)
	// example input: h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin
	// example output:
	//  version: "2.34-210"
	//  major: "2"
	//  minor: "34"
	//  patch: "210"
	// (there are other capture groups, but they can be ignored)
	rightMostVersionIshPattern = regexp.MustCompile(`-(?P<version>(?P<major>[0-9][a-zA-Z0-9]*)(\.(?P<minor>[0-9][a-zA-Z0-9]*))?(\.(?P<patch>0|[1-9][a-zA-Z0-9]*)){0,3}(?:-(?P<prerelease>\d*[.a-zA-Z-][.0-9a-zA-Z-]*)*)?(?:\+(?P<metadata>[.0-9a-zA-Z-]+(?:\.[.0-9a-zA-Z-]+)*))?)`)
)

type Cataloger struct{}

func NewStoreCataloger() *Cataloger {
	return &Cataloger{}
}

func (c *Cataloger) Name() string {
	return catalogerName
}

func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	// we want to search for only directories, which isn't possible via the stereoscope API, so we need to apply the glob manually on all returned paths
	var pkgs []pkg.Package
	var filesByPath = make(map[string]*source.LocationSet)
	for location := range resolver.AllLocations() {
		matchesStorePath, err := doublestar.Match(nixStoreGlob, location.RealPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match nix store path: %w", err)
		}

		parentStorePath := findParentNixStorePath(location.RealPath)
		if parentStorePath != "" {
			if _, ok := filesByPath[parentStorePath]; !ok {
				s := source.NewLocationSet()
				filesByPath[parentStorePath] = &s
			}
			filesByPath[parentStorePath].Add(location)
		}

		if !matchesStorePath {
			continue
		}

		storePath := parseNixStorePath(location.RealPath)

		if storePath == nil || !storePath.isValidPackage() {
			continue
		}

		p := newNixStorePackage(*storePath, location)
		pkgs = append(pkgs, p)
	}

	// add file sets to packages
	for i := range pkgs {
		p := &pkgs[i]
		locations := p.Locations.ToSlice()
		if len(locations) == 0 {
			log.WithFields("package", p.Name).Warn("nix package has no evidence locations associated")
			continue
		}
		parentStorePath := locations[0].RealPath
		files, ok := filesByPath[parentStorePath]
		if !ok {
			log.WithFields("path", parentStorePath, "nix-store-path", parentStorePath).Warn("found a nix store file for a non-existent package")
			continue
		}
		appendFiles(p, files.ToSlice()...)
		continue
	}

	return pkgs, nil, nil
}

func appendFiles(p *pkg.Package, location ...source.Location) {
	metadata, ok := p.Metadata.(pkg.NixStoreMetadata)
	if !ok {
		log.WithFields("package", p.Name).Warn("nix package metadata missing")
		return
	}

	for _, l := range location {
		metadata.Files = append(metadata.Files, l.RealPath)
	}

	if metadata.Files == nil {
		// note: we always have an allocated collection for output
		metadata.Files = []string{}
	}

	p.Metadata = metadata
	p.SetID()
}
