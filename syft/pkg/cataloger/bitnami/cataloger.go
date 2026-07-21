/*
Package bitnami provides a concrete Cataloger implementation for capturing packages embedded within Bitnami SBOM files.
*/
package bitnami

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "bitnami-cataloger"

// NewCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseSBOM,
			"/opt/bitnami/**/.spdx-*.spdx",
		).
		WithParserByGlobs(parseComponentsJSON,
			"/opt/bitnami/.bitnami_components.json",
		)
}

func parseSBOM(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	s, sFormat, _, err := format.Decode(reader)
	if err != nil {
		return nil, nil, err
	}

	if s == nil {
		log.WithFields("path", reader.RealPath).Trace("file is not an SBOM")
		return nil, nil, nil
	}

	// Bitnami exclusively uses SPDX JSON SBOMs
	if sFormat != "spdx-json" {
		log.WithFields("path", reader.RealPath).Trace("file is not an SPDX JSON SBOM")
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	var secondaryPkgsFiles []string
	mainPkgID := findMainPkgID(s.Relationships)
	for _, p := range s.Artifacts.Packages.Sorted() {
		// We only want to report Bitnami packages
		if !strings.HasPrefix(p.PURL, "pkg:bitnami") {
			continue
		}

		p.FoundBy = catalogerName
		p.Type = pkg.BitnamiPkg
		// replace all locations on the package with the location of the SBOM file.
		// Why not keep the original list of locations? Since the "locations" field is meant to capture
		// where there is evidence of this file, and the catalogers have not run against any file other than,
		// the SBOM, this is the only location that is relevant for this cataloger.
		p.Locations = file.NewLocationSet(
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		// Parse the Bitnami-specific metadata
		metadata, err := parseBitnamiPURL(p.PURL)
		if err != nil {
			return nil, nil, err
		}

		// Bitnami packages reported in a SPDX file are shipped under the same directory
		// as the SPDX file itself.
		metadata.Path = filepath.Dir(reader.RealPath)
		if p.ID() != mainPkgID {
			metadata.Files = packageFiles(s.Relationships, p, metadata.Path)
			secondaryPkgsFiles = append(secondaryPkgsFiles, metadata.Files...)
		}

		p.Metadata = metadata

		pkgs = append(pkgs, p)
	}
	// If there is exactly one package, assume it is the main package
	if len(pkgs) == 1 && mainPkgID == "" {
		mainPkgID = pkgs[0].ID()
	}

	// Resolve all files owned by the main package in the SBOM and update the metadata
	if mainPkgFiles, err := mainPkgFiles(resolver, reader.RealPath, secondaryPkgsFiles); err == nil {
		for i, p := range pkgs {
			if p.ID() == mainPkgID {
				metadata, ok := p.Metadata.(*pkg.BitnamiSBOMEntry)
				if !ok {
					log.WithFields("spdx-filepath", reader.RealPath).Trace("main package in SBOM does not have Bitnami metadata")
					continue
				}

				metadata.Files = mainPkgFiles
				pkgs[i].Metadata = metadata
			}
		}
	} else {
		log.WithFields("spdx-filepath", reader.RealPath, "error", err).Trace("unable to resolve owned files for main package in SBOM")
	}

	return pkgs, filterRelationships(s.Relationships, pkgs), nil
}

// filterRelationships filters out relationships that are not related to Bitnami packages
// and replaces the package information with the one with completed info
func filterRelationships(relationships []artifact.Relationship, pkgs []pkg.Package) []artifact.Relationship {
	var result []artifact.Relationship
	for _, r := range relationships {
		if value, ok := r.From.(pkg.Package); ok {
			found := false
			for _, p := range pkgs {
				if value.PURL == p.PURL {
					r.From = p
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if value, ok := r.To.(pkg.Package); ok {
			found := false
			for _, p := range pkgs {
				if value.PURL == p.PURL {
					r.To = p
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		result = append(result, r)
	}

	return result
}

// findMainPkgID goes through the list of relationships and finds the main package ID
// which is the one that contains other packages but is not contained by any other package
func findMainPkgID(relationships []artifact.Relationship) artifact.ID {
	containedByAnother := func(candidateID artifact.ID) bool {
		for _, r := range relationships {
			if r.Type != artifact.ContainsRelationship {
				continue
			}

			if to, ok := r.To.(pkg.Package); ok {
				if to.ID() == candidateID {
					return true
				}
			}
		}

		return false
	}

	for _, r := range relationships {
		if from, ok := r.From.(pkg.Package); ok {
			if !strings.HasPrefix(from.PURL, "pkg:bitnami") {
				continue
			}
			if !containedByAnother(from.ID()) {
				return from.ID()
			}
		}
	}

	return ""
}
