package python

import (
	"context"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type pdmLock struct {
	Metadata struct {
		Groups      []string `toml:"groups"`
		Strategy    []string `toml:"strategy"`
		LockVersion string   `toml:"lock_version"`
		ContentHash string   `toml:"content_hash"`
	} `toml:"metadata"`
	Package []pdmLockPackage `toml:"package"`
}

type pdmLockPackage struct {
	Name           string               `toml:"name"`
	Version        string               `toml:"version"`
	RequiresPython string               `toml:"requires_python"`
	Summary        string               `toml:"summary"`
	Dependencies   []string             `toml:"dependencies"`
	Files          []pdmLockPackageFile `toml:"files"`
}

type pdmLockPackageFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

var _ generic.Parser = parsePdmLock

// parsePdmLock is a parser function for pdm.lock contents, returning python packages discovered.
func parsePdmLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var lock pdmLock
	_, err := toml.NewDecoder(reader).Decode(&lock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse pdm.lock file: %w", err)
	}

	var relationshipsHash = make(map[string][]string)
	var pkgs = make(map[string]pkg.Package)
	for _, p := range lock.Package {
		relationshipsHash[p.Name] = p.Dependencies

		var files []pkg.PythonFileRecord
		for _, file := range p.Files {
			if colonIndex := strings.Index(file.Hash, ":"); colonIndex != -1 {
				algorithm := file.Hash[:colonIndex]
				value := file.Hash[colonIndex+1:]

				files = append(files, pkg.PythonFileRecord{
					Path: file.File,
					Digest: &pkg.PythonFileDigest{
						Algorithm: algorithm,
						Value:     value,
					},
				})
			}
		}

		pythonPkgMetadata := pkg.PythonPdmLockEntry{
			Name:    p.Name,
			Version: p.Version,
			Files:   files,
			Summary: p.Summary,
		}

		pkgs[p.Name] = newPackageForIndexWithMetadata(
			p.Name,
			p.Version,
			pythonPkgMetadata,
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
	}

	relationships := buildPdmRelationships(pkgs, relationshipsHash)

	// Create array only at the end
	var pkgsArray []pkg.Package
	for _, v := range pkgs {
		pkgsArray = append(pkgsArray, v)
	}
	pkg.Sort(pkgsArray)

	return pkgsArray, relationships, unknown.IfEmptyf(pkgsArray, "unable to determine packages")
}

func buildPdmRelationships(pkgs map[string]pkg.Package, relationshipsHash map[string][]string) []artifact.Relationship {
	// Map: source package name -> set of target package names
	depMap := make(map[string]map[string]bool)

	for pkgName := range pkgs {
		for _, dep := range relationshipsHash[pkgName] {
			// Handle environment markers (semicolon)
			depName := strings.Split(dep, ";")[0]
			// Handle version specifiers
			depName = strings.Split(depName, "<")[0]
			depName = strings.Split(depName, ">")[0]
			depName = strings.Split(depName, "=")[0]
			depName = strings.Split(depName, "~")[0]
			depName = strings.TrimSpace(depName)
			if depName == "" {
				continue
			}

			if _, exists := pkgs[depName]; exists {
				if depMap[pkgName] == nil {
					depMap[pkgName] = make(map[string]bool)
				}
				depMap[pkgName][depName] = true
			}
		}
	}

	// Convert to relationships
	var relationships []artifact.Relationship
	for sourceName, targets := range depMap {
		sourcePackage := pkgs[sourceName]
		for targetName := range targets {
			targetPackage := pkgs[targetName]
			relationships = append(relationships, artifact.Relationship{
				From: sourcePackage,
				To:   targetPackage,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	return relationships
}
