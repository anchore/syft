package nix

import (
	"fmt"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const (
	catalogerName = "nix-store-cataloger"
	nixStoreGlob  = "**/nix/store/*"
)

// StoreCataloger finds package outputs installed in the Nix store location (/nix/store/*).
type StoreCataloger struct{}

func NewStoreCataloger() *StoreCataloger {
	return &StoreCataloger{}
}

func (c *StoreCataloger) Name() string {
	return catalogerName
}

func (c *StoreCataloger) Catalog(resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// we want to search for only directories, which isn't possible via the stereoscope API, so we need to apply the glob manually on all returned paths
	var pkgs []pkg.Package
	var filesByPath = make(map[string]*file.LocationSet)
	for location := range resolver.AllLocations() {
		matchesStorePath, err := doublestar.Match(nixStoreGlob, location.RealPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to match nix store path: %w", err)
		}

		parentStorePath := findParentNixStorePath(location.RealPath)
		if parentStorePath != "" {
			if _, ok := filesByPath[parentStorePath]; !ok {
				s := file.NewLocationSet()
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

		p := newNixStorePackage(*storePath, location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
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
	}

	return pkgs, nil, nil
}

func appendFiles(p *pkg.Package, location ...file.Location) {
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
