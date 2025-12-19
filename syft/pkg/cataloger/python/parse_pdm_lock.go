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
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
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
	Marker         string               `toml:"marker"`
	Dependencies   []string             `toml:"dependencies"`
	Extras         []string             `toml:"extras"`
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

// mergePdmLockPackages merges multiple package entries (with different extras) into a single PythonPdmLockEntry.
//
// PDM vs Poetry Lock File Behavior:
//
// PDM creates separate [[package]] entries in the lock file for each extras combination that is actually used
// in the dependency tree. For example, if your project depends on coverage[toml], PDM will create TWO entries:
//  1. A base "coverage" package entry (no extras field)
//  2. A "coverage" package entry with extras = ["toml"] and its own dependencies
//
// Poetry, in contrast, creates a SINGLE package entry per package and uses conditional markers to indicate
// when extra dependencies should be included.
//
// SBOM Representation:
//
// Semantically, "coverage" and "coverage[toml]" are NOT separate packages - they represent the same package
// with optional features enabled. The [toml] syntax is Python's way of requesting optional dependencies.
// Therefore, in the SBOM we create a SINGLE package node per name+version to accurately represent that:
//
//   - There is one logical package (e.g., "coverage")
//   - The package may be used with different feature sets (extras) by different dependents
//   - For example: "pytest-cov" depends on "coverage[toml]" while another package might depend on base "coverage"
//
// This function consolidates PDM's multiple entries into:
//   - Base package metadata (files, summary, dependencies without extras)
//   - Extras variants (each combination of extras with its specific dependencies)
//
// This approach ensures dependency resolution works correctly: when a package requires "coverage[toml]",
// the dependency resolver can match it to the "coverage" package node and its "toml" variant.
func mergePdmLockPackages(packages []pdmLockPackage) pkg.PythonPdmLockEntry {
	if len(packages) == 0 {
		return pkg.PythonPdmLockEntry{}
	}

	var entry pkg.PythonPdmLockEntry
	var baseFiles []pkg.PythonPdmFileEntry

	// Separate base package from extras variants
	// note: this logic processes packages in order and assumes the base package (no extras) appears
	// before extras variants in the PDM lock file, which is PDM's current behavior
	for _, p := range packages {
		// Convert files format
		var files []pkg.PythonPdmFileEntry
		for _, f := range p.Files {
			// skip files with invalid hash format (missing colon separator between algorithm and value)
			if colonIndex := strings.Index(f.Hash, ":"); colonIndex != -1 {
				algorithm := f.Hash[:colonIndex]
				value := f.Hash[colonIndex+1:]

				files = append(files, pkg.PythonPdmFileEntry{
					URL: f.File,
					Digest: pkg.PythonFileDigest{
						Algorithm: algorithm,
						Value:     value,
					},
				})
			}
		}

		// Base package (no extras field or empty extras)
		if len(p.Extras) == 0 {
			entry.Summary = p.Summary
			entry.RequiresPython = p.RequiresPython
			entry.Dependencies = p.Dependencies
			entry.Marker = p.Marker
			baseFiles = files
		} else {
			// Extras variant
			variant := pkg.PythonPdmLockExtraVariant{
				Extras:       p.Extras,
				Dependencies: p.Dependencies,
				Marker:       p.Marker,
			}

			// Only include files if different from base
			// For now, we'll compare lengths as a simple check
			if len(baseFiles) == 0 || !filesEqual(baseFiles, files) {
				variant.Files = files
			}

			entry.Extras = append(entry.Extras, variant)
		}
	}

	// Store base files
	entry.Files = baseFiles

	// If no base package was found but we have extras, use first package's metadata as base
	if entry.Summary == "" && len(packages) > 0 {
		entry.Summary = packages[0].Summary
		entry.RequiresPython = packages[0].RequiresPython
		entry.Dependencies = packages[0].Dependencies
		entry.Marker = packages[0].Marker
	}

	return entry
}

// filesEqual checks if two file slices are equal by comparing URL and digest fields.
// assumes files appear in the same order in both slices.
func filesEqual(a, b []pkg.PythonPdmFileEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].URL != b[i].URL || a[i].Digest.Algorithm != b[i].Digest.Algorithm || a[i].Digest.Value != b[i].Digest.Value {
			return false
		}
	}
	return true
}

// parsePdmLock is a parser function for pdm.lock contents, returning python packages discovered.
func (plp pdmLockParser) parsePdmLock(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var lock pdmLock
	_, err := toml.NewDecoder(reader).Decode(&lock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse pdm.lock file: %w", err)
	}

	// Group packages by name@version since PDM creates separate entries for different extras combinations
	packageGroups := make(map[string][]pdmLockPackage)
	for _, p := range lock.Package {
		key := p.Name + "@" + p.Version
		packageGroups[key] = append(packageGroups[key], p)
	}

	// Merge package groups and create packages
	var pkgs []pkg.Package
	for _, group := range packageGroups {
		if len(group) == 0 {
			continue
		}

		// Use first package for name/version (same across all entries in group)
		name := group[0].Name
		version := group[0].Version

		// Merge all entries into single metadata
		pythonPkgMetadata := mergePdmLockPackages(group)

		pkgs = append(pkgs, newPackageForIndexWithMetadata(
			ctx,
			plp.licenseResolver,
			name,
			version,
			pythonPkgMetadata,
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		))
	}

	relationships := dependency.Resolve(pdmLockDependencySpecifier, pkgs)

	return pkgs, relationships, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
