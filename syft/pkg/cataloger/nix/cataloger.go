/*
Package nix provides a concrete Cataloger implementation for packages within the Nix packaging ecosystem.
*/
package nix

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const catalogerName = "nix-store-cataloger"

// storeCataloger finds package outputs installed in the Nix store location (/nix/store/*).
type storeCataloger struct{}

func NewStoreCataloger() pkg.Cataloger {
	return &storeCataloger{}
}

func (c *storeCataloger) Name() string {
	return catalogerName
}

// Find the parent Nix store path for a given path
func findParentNixStorePath(path string) string {
	// Handle standard /nix/store/ paths
	parts := strings.Split(path, "/")
	for i := 0; i < len(parts)-2; i++ {
		if parts[i] == "nix" && parts[i+1] == "store" && i+2 < len(parts) {
			// Check if it matches the hash-name pattern
			storeItem := parts[i+2]
			if matched, _ := regexp.MatchString(`^[a-z0-9]{32}-.*`, storeItem); matched {
				return filepath.Join("/", filepath.Join(parts[:i+3]...))
			}
		}
	}

	// Handle short-form Nix paths (without the /nix/store/ prefix)
	// These would be paths like /[hash]-[package-name]/...
	shortPathPattern := regexp.MustCompile(`^/([a-z0-9]{32}-[^/]+)`)
	if matches := shortPathPattern.FindStringSubmatch(path); len(matches) == 2 {
		return "/" + matches[1]
	}

	return ""
}

func (c *storeCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// we want to search for only directories, which isn't possible via the stereoscope API, so we need to apply the glob manually on all returned paths
	var pkgs []pkg.Package
	var filesByPath = make(map[string]*file.LocationSet)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for location := range resolver.AllLocations(ctx) {
		matchesStorePath, err := doublestar.Match("**/nix/store/*", location.RealPath)
		if err != nil {
			log.Debugf("Error matching path %s: %v", location.RealPath, err)
			return nil, nil, fmt.Errorf("failed to match nix store path: %w", err)
		}
		if !matchesStorePath {
			// Check if this is a "short-form" Nix store path (without the /nix/store/ prefix)
			// This pattern matches paths like /[hash]-[package-name]/...
			shortPathPattern := regexp.MustCompile(`^/([a-z0-9]{32})-([^/]+)`)
			if shortPathPattern.MatchString(location.RealPath) {
				matchesStorePath = true
				log.Debugf("Matched short-form Nix path: %s", location.RealPath)
			}
		}

		if !matchesStorePath {
			log.Debugf("Not a Nix store path: %s", location.RealPath)
			continue
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
			log.Debugf("Not a Nix store path: %s", location.RealPath)
			continue
		}

		storePath := parseNixStorePath(location.RealPath)
		if storePath == nil {
			log.Debugf("Failed to parse Nix path: %s", location.RealPath)
			continue
		}

		// Only create packages for non-derivation/source paths
		if storePath.shouldIncludeAsPackage() {
			p := newNixStorePackage(*storePath, location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
			pkgs = append(pkgs, p)
		} else {
			log.Debugf("Skipping non-package path: %s (type: %s)", location.RealPath, storePath.pathType)
		}

	}

	// add file sets to packages
	for i := range pkgs {
		p := &pkgs[i]
		locations := p.Locations.ToSlice()
		if len(locations) == 0 {
			log.WithFields("package", p.Name).Debug("nix package has no evidence locations associated")
			continue
		}
		parentStorePath := locations[0].RealPath
		files, ok := filesByPath[parentStorePath]
		if !ok {
			log.WithFields("path", parentStorePath, "nix-store-path", parentStorePath).Debug("found a nix store file for a non-existent package")
			continue
		}
		appendFiles(p, files.ToSlice()...)
	}

	// After all packages are created, enrich them with derivation data
	for i := range pkgs {
		p := &pkgs[i]
		metadata, ok := p.Metadata.(pkg.NixStoreEntry)
		if !ok {
			continue
		}

		// Find and parse the derivation file
		derivPath := findDeriverPath(metadata.Path)
		if derivPath != "" {
			if deriv, err := ParseDerivation(derivPath); err == nil {
				// Enrich package metadata with derivation data
				if deriv.PName != "" {
					p.Name = deriv.PName
				}
				if deriv.Version != "" {
					p.Version = deriv.Version
				}

				// Add license, homepage, etc. to metadata
				metadata.License = deriv.License
				metadata.Homepage = deriv.Homepage
				metadata.Description = deriv.Description
				metadata.DeriverPath = derivPath

				// Update the package metadata
				p.Metadata = metadata
			}
		}
	}

	// Find and add relationships between packages
	relationships, err := findDependencies(pkgs)
	if err != nil {
		log.Warnf("failed to resolve nix dependencies: %v", err)
	}
	// Deduplicate packages based on name and version
	dedupedPkgs := deduplicateNixPackages(pkgs)
	pkgs = dedupedPkgs
	return pkgs, relationships, nil
}

// ensureNixStorePrefix makes sure the path has the /nix/store/ prefix
func ensureNixStorePrefix(path string) string {
	// Check if the path already has the /nix/store/ prefix
	if strings.Contains(path, "/nix/store/") {
		return path
	}

	// Check if this is a short-form path starting with /[hash]-[name]
	shortPathPattern := regexp.MustCompile(`^/([a-z0-9]{32}-[^/]+)(.*)$`)
	if matches := shortPathPattern.FindStringSubmatch(path); len(matches) >= 3 {
		// Convert short form path to full path with /nix/store/ prefix
		return "/nix/store/" + matches[1] + matches[2]
	}

	return path
}

func appendFiles(p *pkg.Package, location ...file.Location) {
	metadata, ok := p.Metadata.(pkg.NixStoreEntry)
	if !ok {
		log.WithFields("package", p.Name).Debug("nix package metadata missing")
		return
	}

	for _, l := range location {
		// Normalize the path to ensure it has the /nix/store/ prefix
		normalizedPath := ensureNixStorePrefix(l.RealPath)
		metadata.Files = append(metadata.Files, normalizedPath)
	}

	if metadata.Files == nil {
		// note: we always have an allocated collection for output
		metadata.Files = []string{}
	}

	p.Metadata = metadata
	p.SetID()
}
