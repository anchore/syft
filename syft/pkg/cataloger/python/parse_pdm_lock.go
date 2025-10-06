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
		relationshipsHash[p.Name] = p.Dependencies // array of strings like "aiohttp<4.0.0,>=3.9.2"

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

	var pkgsArray []pkg.Package
	for _, v := range pkgs {
			pkgsArray = append(pkgsArray, v)
	}
	pkg.Sort(pkgsArray)

	var relationships []artifact.Relationship
	relationshipSet := make(map[string]bool) // To avoid duplicate relationships

	for _, pkg := range pkgsArray {
		for _, dep := range relationshipsHash[pkg.Name] {
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

			// Only create relationship if the target package exists
			if targetPkg, exists := pkgs[depName]; exists {
				// Create a unique key to avoid duplicates
				relKey := fmt.Sprintf("%s->%s", pkg.Name, depName)
				if !relationshipSet[relKey] {
					relationshipSet[relKey] = true
					relationships = append(relationships, artifact.Relationship{
						From: pkg,
						To:   targetPkg,
						Type: artifact.DependencyOfRelationship,
					})
				}
			}
		}
	}


	return pkgsArray, relationships, unknown.IfEmptyf(pkgsArray, "unable to determine packages")
}
