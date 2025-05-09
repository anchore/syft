package dotnet

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const (
	depsJSONGlob = "**/*.deps.json"
	dllGlob      = "**/*.dll"
	exeGlob      = "**/*.exe"
)

// depsBinaryCataloger will search for both deps.json evidence and PE file evidence to create packages. All packages
// from both sources are raised up, but with one merge operation applied; If a deps.json package reference can be
// correlated with a PE file, the PE file is attached to the package as supporting evidence.
type depsBinaryCataloger struct {
	config CatalogerConfig
}

func (c depsBinaryCataloger) Name() string {
	return "dotnet-deps-binary-cataloger"
}

func (c depsBinaryCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	depJSONDocs, unknowns, err := findDepsJSON(resolver)
	if err != nil {
		return nil, nil, err
	}

	peFiles, ldpeUnknownErr, err := findPEFiles(resolver)
	if err != nil {
		return nil, nil, err
	}
	if ldpeUnknownErr != nil {
		unknowns = unknown.Join(unknowns, ldpeUnknownErr)
	}

	// partition the logical PE files by location and pair them with the logicalDepsJSON
	pairedDepsJSONs, remainingPeFiles, remainingDepsJSONs := partitionPEs(depJSONDocs, peFiles)

	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	depDocGroups := [][]logicalDepsJSON{pairedDepsJSONs}

	if !c.config.DepPackagesMustHaveDLL {
		depDocGroups = append(depDocGroups, remainingDepsJSONs)
	}

	for _, docs := range depDocGroups {
		for _, doc := range docs {
			ps, rs := packagesFromLogicalDepsJSON(doc, c.config)
			pkgs = append(pkgs, ps...)
			relationships = append(relationships, rs...)
		}
	}

	for _, pe := range remainingPeFiles {
		pkgs = append(pkgs, newDotnetBinaryPackage(pe.VersionResources, pe.Location))
	}

	return pkgs, relationships, unknowns
}

// partitionPEs pairs PE files with the deps.json based on directory containment.
func partitionPEs(depJsons []logicalDepsJSON, peFiles []logicalPE) ([]logicalDepsJSON, []logicalPE, []logicalDepsJSON) {
	// sort deps.json paths from longest to shortest. This is so we are processing the most specific match first.
	sort.Slice(depJsons, func(i, j int) bool {
		return len(depJsons[i].Location.RealPath) > len(depJsons[j].Location.RealPath)
	})

	peFilesByPath := make(map[file.Coordinates][]logicalPE)
	var remainingPeFiles []logicalPE
	for _, pe := range peFiles {
		var found bool
		for i := range depJsons {
			dep := &depJsons[i]
			if isParentOf(dep.Location.RealPath, pe.Location.RealPath) && attachAssociatedExecutables(dep, pe) {
				peFilesByPath[dep.Location.Coordinates] = append(peFilesByPath[dep.Location.Coordinates], pe)
				found = true
				// note: we cannot break from the dep JSON search since the same binary could be associated with multiple packages
				// across multiple deps.json files.
			}
		}
		if !found {
			remainingPeFiles = append(remainingPeFiles, pe)
		}
	}

	var pairedDepsJSON []logicalDepsJSON
	var remainingDepsJSON []logicalDepsJSON

	for _, dep := range depJsons {
		if _, ok := peFilesByPath[dep.Location.Coordinates]; !ok {
			remainingDepsJSON = append(remainingDepsJSON, dep)
		} else {
			pairedDepsJSON = append(pairedDepsJSON, dep)
		}
	}

	return pairedDepsJSON, remainingPeFiles, remainingDepsJSON
}

// attachAssociatedExecutables looks for PE files matching runtime or resource entries
// and attaches them to the appropriate package.
func attachAssociatedExecutables(dep *logicalDepsJSON, pe logicalPE) bool {
	appDir := path.Dir(dep.Location.RealPath)
	relativeDllPath := strings.TrimPrefix(strings.TrimPrefix(pe.Location.RealPath, appDir), "/")

	var found bool
	for key, p := range dep.PackagesByNameVersion {
		if targetPath, ok := p.RuntimePathsByRelativeDLLPath[relativeDllPath]; ok {
			pe.TargetPath = targetPath
			p.Executables = append(p.Executables, pe)
			dep.PackagesByNameVersion[key] = p // update the map with the modified package
			found = true
			continue
		}

		if targetPath, ok := p.ResourcePathsByRelativeDLLPath[relativeDllPath]; ok {
			pe.TargetPath = targetPath
			p.Executables = append(p.Executables, pe)
			dep.PackagesByNameVersion[key] = p // update the map with the modified package
			found = true
		}
	}
	return found
}

var libPrefixPattern = regexp.MustCompile(`^lib/net[^/]+/`)

// trimLibPrefix removes prefixes like "lib/net6.0/" from a path.
func trimLibPrefix(s string) string {
	if match := libPrefixPattern.FindString(s); match != "" {
		parts := strings.Split(s, "/")
		if len(parts) > 2 {
			return strings.Join(parts[2:], "/")
		}
	}
	return s
}

// isParentOf checks if parentFile's directory is a prefix of childFile's directory.
func isParentOf(parentFile, childFile string) bool {
	parentDir := path.Dir(parentFile)
	childDir := path.Dir(childFile)
	return strings.HasPrefix(childDir, parentDir)
}

// packagesFromDepsJSON creates packages from a list of logicalDepsJSON documents.
func packagesFromDepsJSON(docs []logicalDepsJSON, config CatalogerConfig) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	for _, ldj := range docs {
		ps, rs := packagesFromLogicalDepsJSON(ldj, config)
		pkgs = append(pkgs, ps...)
		relationships = append(relationships, rs...)
	}
	return pkgs, relationships
}

// packagesFromLogicalDepsJSON converts a logicalDepsJSON (using the new map type) into catalog packages.
func packagesFromLogicalDepsJSON(doc logicalDepsJSON, config CatalogerConfig) ([]pkg.Package, []artifact.Relationship) {
	var rootPkg *pkg.Package
	if rootLpkg, hasRoot := doc.RootPackage(); !hasRoot {
		rootPkg = newDotnetDepsPackage(rootLpkg, doc.Location)
	}

	var pkgs []pkg.Package
	pkgMap := make(map[string]pkg.Package)
	if rootPkg != nil {
		pkgs = append(pkgs, *rootPkg)
		pkgMap[createNameAndVersion(rootPkg.Name, rootPkg.Version)] = *rootPkg
	}

	nameVersions := doc.PackageNameVersions.List()
	sort.Strings(nameVersions)

	// process each non-root package
	skippedDepPkgs := make(map[string]logicalDepsJSONPackage)
	for _, nameVersion := range nameVersions {
		name, version := extractNameAndVersion(nameVersion)
		if rootPkg != nil && name == rootPkg.Name && version == rootPkg.Version {
			continue
		}
		lp := doc.PackagesByNameVersion[nameVersion]
		if config.DepPackagesMustHaveDLL && len(lp.Executables) == 0 {
			// could not find a paired DLL and the user required this...
			skippedDepPkgs[nameVersion] = lp
			continue
		}

		claimsDLLs := len(lp.RuntimePathsByRelativeDLLPath) > 0 || len(lp.ResourcePathsByRelativeDLLPath) > 0

		if config.DepPackagesMustClaimDLL && !claimsDLLs {
			if config.RelaxDLLClaimsWhenBundlingDetected && !doc.BundlingDetected || !config.RelaxDLLClaimsWhenBundlingDetected {
				// could not find a runtime or resource path and the user required this...
				// and there is no evidence of a bundler in the dependencies (e.g. ILRepack)
				skippedDepPkgs[nameVersion] = lp
				continue
			}
		}

		dotnetPkg := newDotnetDepsPackage(lp, doc.Location)
		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[nameVersion] = *dotnetPkg
		}
	}

	return pkgs, relationshipsFromLogicalDepsJSON(doc, pkgMap, skippedDepPkgs)
}

// relationshipsFromLogicalDepsJSON creates relationships from a logicalDepsJSON document for only the given syft packages.
// It is possible that the document describes more packages than that is provided as syft packages, in which cases
// those relationships will not be created. If there are any skipped packages, we still want to logically represent
// dependency relationships, jumping over the skipped packages.
func relationshipsFromLogicalDepsJSON(doc logicalDepsJSON, pkgMap map[string]pkg.Package, skipped map[string]logicalDepsJSONPackage) []artifact.Relationship {
	var relationships []artifact.Relationship
	for _, lp := range doc.PackagesByNameVersion {
		if lp.Targets == nil {
			continue
		}
		for depName, depVersion := range lp.Targets.Dependencies {
			depNameVersion := createNameAndVersion(depName, depVersion)
			thisPkg, ok := pkgMap[lp.NameVersion]
			if !ok {
				continue
			}

			var depPkgs []pkg.Package
			depPkg, ok := pkgMap[depNameVersion]
			if !ok {
				skippedDepPkg, ok := skipped[depNameVersion]
				if !ok {
					// this package wasn't explicitly skipped, so it could be a malformed deps.json file
					// ignore this case and do not create a relationships
					continue
				}
				// we have a skipped package, so we need to create a relationship but looking a the nearest
				// package with an associated PE file for even dependency listed on the skipped package.
				// Take note that the skipped depedency's dependency could also be skipped, so we need to
				// do this recursively.
				depPkgs = findNearestDependencyPackages(skippedDepPkg, pkgMap, skipped, strset.New())
			} else {
				depPkgs = append(depPkgs, depPkg)
			}

			for _, d := range depPkgs {
				rel := artifact.Relationship{
					From: d,
					To:   thisPkg,
					Type: artifact.DependencyOfRelationship,
				}
				relationships = append(relationships, rel)
			}
		}
	}

	relationship.Sort(relationships)
	return relationships
}

func findNearestDependencyPackages(skippedDep logicalDepsJSONPackage, pkgMap map[string]pkg.Package, skipped map[string]logicalDepsJSONPackage, processed *strset.Set) []pkg.Package {
	var nearestPkgs []pkg.Package

	// if we have already processed this package, skip it to avoid infinite recursion
	if processed.Has(skippedDep.NameVersion) {
		return nearestPkgs
	}

	processed.Add(skippedDep.NameVersion)

	for depName, depVersion := range skippedDep.Targets.Dependencies {
		depNameVersion := createNameAndVersion(depName, depVersion)
		depPkg, ok := pkgMap[depNameVersion]
		if !ok {
			skippedDepPkg, ok := skipped[depNameVersion]
			if !ok {
				// this package wasn't explicitly skipped, so it could be a malformed deps.json file
				// ignore this case and do not create a relationships
				continue
			}

			nearestPkgs = append(nearestPkgs, findNearestDependencyPackages(skippedDepPkg, pkgMap, skipped, processed)...)
		} else {
			nearestPkgs = append(nearestPkgs, depPkg)
		}
	}
	return nearestPkgs
}

// findDepsJSON locates and parses all deps.json files.
func findDepsJSON(resolver file.Resolver) ([]logicalDepsJSON, error, error) {
	locs, err := resolver.FilesByGlob(depsJSONGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find deps.json files: %w", err)
	}

	var depsJSONs []logicalDepsJSON
	var unknownErr error
	for _, loc := range locs {
		dj, err := readDepsJSON(resolver, loc)
		if err != nil {
			unknownErr = unknown.Append(unknownErr, loc, err)
			continue
		}

		depsJSONs = append(depsJSONs, getLogicalDepsJSON(*dj))
	}

	return depsJSONs, unknownErr, nil
}

// readDepsJSON reads and parses a single deps.json file.
func readDepsJSON(resolver file.Resolver, loc file.Location) (*depsJSON, error) {
	reader, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return nil, unknown.New(loc, fmt.Errorf("unable to read deps.json file: %w", err))
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	dj, err := newDepsJSON(file.NewLocationReadCloser(loc, reader))
	if err != nil {
		return nil, unknown.New(loc, fmt.Errorf("unable to parse deps.json file: %w", err))
	}

	if dj == nil {
		return nil, unknown.New(loc, fmt.Errorf("expected to find packages in deps.json but did not: %q", loc.RealPath))
	}

	return dj, nil
}

// findPEFiles locates and parses all PE files (dll/exe).
func findPEFiles(resolver file.Resolver) ([]logicalPE, error, error) {
	peLocs, err := resolver.FilesByGlob(dllGlob, exeGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find PE files: %w", err)
	}

	var peFiles []logicalPE
	var unknownErr error
	for _, loc := range peLocs {
		ldpe, err := readPEFile(resolver, loc)
		if err != nil {
			unknownErr = unknown.Append(unknownErr, loc, err)
			continue
		}
		if ldpe == nil {
			continue
		}
		peFiles = append(peFiles, *ldpe)
	}

	return peFiles, unknownErr, nil
}

// readPEFile reads and parses a single PE file.
func readPEFile(resolver file.Resolver, loc file.Location) (*logicalPE, error) {
	reader, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return nil, unknown.New(loc, fmt.Errorf("unable to read PE file: %w", err))
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	ldpe, err := getLogicalDotnetPE(file.NewLocationReadCloser(loc, reader))
	if err != nil {
		return nil, unknown.New(loc, fmt.Errorf("unable to parse PE file: %w", err))
	}

	if ldpe == nil {
		return nil, nil
	}

	if !ldpe.CLR.hasEvidenceOfCLR() {
		// this is not a .NET binary
		return nil, nil
	}

	return ldpe, nil
}
