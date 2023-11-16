package cpp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseConaninfo

func parseConanMetadataFromFilePath(path string) (pkg.ConaninfoEntry, error) {
	//	fullFilePath = str(reader.Location.AccessPath)
	// Split the full patch into the folders we expect. I.e.:
	// $HOME/.conan/data/<pkg-name>/<pkg-version>/<user>/<channel>/package/<package_id>/conaninfo.txt
	re := regexp.MustCompile(`.*[/\\](?P<name>[^/\\]+)[/\\](?P<version>[^/\\]+)[/\\](?P<user>[^/\\]+)[/\\](?P<channel>[^/\\]+)[/\\]package[/\\](?P<id>[^/\\]+)[/\\]conaninfo\.txt`)
	matches := re.FindStringSubmatch(path)
	if len(matches) != 6 {
		return pkg.ConaninfoEntry{}, fmt.Errorf("failed to get parent package info from conaninfo file path")
	}
	mainPackageRef := fmt.Sprintf("%s/%s@%s/%s", matches[1], matches[2], matches[3], matches[4])
	return pkg.ConaninfoEntry{
		Ref:       mainPackageRef,
		PackageID: matches[5],
	}, nil
}

func getRelationships(pkgs []pkg.Package, mainPackageRef pkg.Package) []artifact.Relationship {
	var relationships []artifact.Relationship
	for _, p := range pkgs {
		// this is a pkg that package "main_package" depends on... make a relationship
		relationships = append(relationships, artifact.Relationship{
			From: p,
			To:   mainPackageRef,
			Type: artifact.DependencyOfRelationship,
		})
	}
	return relationships
}

func parseFullRequiresLine(line string, reader file.LocationReadCloser, pkgs *[]pkg.Package) {
	if len(line) == 0 {
		return
	}

	cref := splitConanRef(line)

	meta := pkg.ConaninfoEntry{
		Ref:       line,
		PackageID: cref.PackageID,
	}

	p := newConaninfoPackage(
		meta,
		reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)
	if p != nil {
		*pkgs = append(*pkgs, *p)
	}
}

// parseConaninfo is a parser function for conaninfo.txt contents, returning all packages discovered.
// The conaninfo.txt file is typically present for an installed conan package under:
// $HOME/.conan/data/<pkg-name>/<pkg-version>/<user>/<channel>/package/<package_id>/conaninfo.txt
// Based on the relative path we can get:
// - package name
// - package version
// - package id
// - user
// - channel
// The conaninfo.txt gives:
// - package requires (full_requires)
// - recipe revision (recipe_hash)
func parseConaninfo(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// First set the base package info by checking the relative path
	fullFilePath := string(reader.Location.LocationData.Reference().RealPath)
	if len(fullFilePath) == 0 {
		fullFilePath = reader.Location.LocationData.RealPath
	}

	mainMetadata, err := parseConanMetadataFromFilePath(fullFilePath)
	if err != nil {
		return nil, nil, err
	}

	r := bufio.NewReader(reader)
	inRequirements := false
	inRecipeHash := false
	var pkgs []pkg.Package

	for {
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(io.EOF, err):
			mainPackage := newConaninfoPackage(
				mainMetadata,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			)

			mainPackageRef := *mainPackage
			relationships := getRelationships(pkgs, mainPackageRef)

			pkgs = append(pkgs, mainPackageRef)

			return pkgs, relationships, nil
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse conaninfo.txt file: %w", err)
		}

		switch {
		case strings.Contains(line, "[full_requires]"):
			inRequirements = true
			inRecipeHash = false
			continue
		case strings.Contains(line, "[recipe_hash]"):
			inRequirements = false
			inRecipeHash = true
			continue
		case strings.ContainsAny(line, "[]") || strings.HasPrefix(strings.TrimSpace(line), "#"):
			inRequirements = false
			inRecipeHash = false
			continue
		}

		if inRequirements {
			parseFullRequiresLine(strings.Trim(line, "\n "), reader, &pkgs)
		}
		if inRecipeHash {
			// add recipe hash to the metadata ref
			mainMetadata.Ref = mainMetadata.Ref + "#" + strings.Trim(line, "\n ")
			inRecipeHash = false
		}
	}
}
