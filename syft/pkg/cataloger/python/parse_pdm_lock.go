package python

import (
	"context"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/scylladb/go-set/strset"

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

type pdmLockParser struct {
	cfg             CatalogerConfig
	licenseResolver pythonLicenseResolver
}

func newPdmLockParser(cfg CatalogerConfig) pdmLockParser {
	return pdmLockParser{
		cfg:             cfg,
		licenseResolver: newPythonLicenseResolver(cfg),
	}
}

// parsePdmLock is a parser function for pdm.lock contents, returning python packages discovered.
func (plp pdmLockParser) parsePdmLock(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var lock pdmLock
	_, err := toml.NewDecoder(reader).Decode(&lock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse pdm.lock file: %w", err)
	}

	var pkgs []pkg.Package
	for _, p := range lock.Package {
		var files []pkg.PythonFileRecord
		for _, f := range p.Files {
			if colonIndex := strings.Index(f.Hash, ":"); colonIndex != -1 {
				algorithm := f.Hash[:colonIndex]
				value := f.Hash[colonIndex+1:]

				files = append(files, pkg.PythonFileRecord{
					Path: f.File,
					Digest: &pkg.PythonFileDigest{
						Algorithm: algorithm,
						Value:     value,
					},
				})
			}
		}

		// only store used part of the dependency information
		var deps []string
		for _, dep := range p.Dependencies {
			// remove environment markers (after semicolon)
			dep = strings.Split(dep, ";")[0]
			dep = strings.TrimSpace(dep)
			if dep != "" {
				deps = append(deps, dep)
			}
		}

		pythonPkgMetadata := pkg.PythonPdmLockEntry{
			Files:        files,
			Summary:      p.Summary,
			Dependencies: deps,
		}

		pkgs = append(pkgs, newPackageForIndexWithMetadata(
			ctx,
			plp.licenseResolver,
			p.Name,
			p.Version,
			pythonPkgMetadata,
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		))
	}

	relationships := buildPdmRelationships(pkgs)

	return pkgs, relationships, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func buildPdmRelationships(pkgs []pkg.Package) []artifact.Relationship {
	pkgMap := make(map[string]pkg.Package, len(pkgs))
	for _, p := range pkgs {
		pkgMap[p.Name] = p
	}

	var relationships []artifact.Relationship
	for _, p := range pkgs {
		meta, ok := p.Metadata.(pkg.PythonPdmLockEntry)
		if !ok {
			continue
		}

		// collect unique dependencies
		added := strset.New()

		for _, depName := range meta.Dependencies {
			// Handle version specifiers
			depName = strings.Split(depName, "<")[0]
			depName = strings.Split(depName, ">")[0]
			depName = strings.Split(depName, "=")[0]
			depName = strings.Split(depName, "~")[0]
			depName = strings.TrimSpace(depName)

			if depName == "" || added.Has(depName) {
				continue
			}
			added.Add(depName)

			if dep, exists := pkgMap[depName]; exists {
				relationships = append(relationships, artifact.Relationship{
					From: dep,
					To:   p,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}

	return relationships
}
