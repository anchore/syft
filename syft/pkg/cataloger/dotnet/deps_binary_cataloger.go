package dotnet

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

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
	pairedDepsJSON, remainingPeFiles, remainingDepsJSON := partitionPEs(depJSONDocs, peFiles)

	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	for _, docs := range [][]logicalDepsJSON{pairedDepsJSON, remainingDepsJSON} {
		for _, doc := range docs {
			ps, rs := packagesFromLogicalDepsJSON(doc)
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
func partitionPEs(depJsons []logicalDepsJSON, peFiles []logicalDotnetPE) ([]logicalDepsJSON, []logicalDotnetPE, []logicalDepsJSON) {
	// sort deps.json paths from longest to shortest. This is so we are processing the most specific match first.
	sort.Slice(depJsons, func(i, j int) bool {
		return len(depJsons[i].Location.RealPath) > len(depJsons[j].Location.RealPath)
	})

	peFilesByPath := make(map[file.Coordinates][]logicalDotnetPE)
	var remainingPeFiles []logicalDotnetPE
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
func attachAssociatedExecutables(dep *logicalDepsJSON, pe logicalDotnetPE) bool {
	appDir := path.Dir(dep.Location.RealPath)
	relativeDllPath := strings.TrimPrefix(strings.TrimPrefix(pe.Location.RealPath, appDir), "/")

	var found bool
	for key, p := range dep.PackagesByNameVersion {
		if targetPath, ok := p.RuntimeAndResourcePathsByRelativeDLLPath[relativeDllPath]; ok {
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
func packagesFromDepsJSON(docs []logicalDepsJSON) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	for _, ldj := range docs {
		ps, rs := packagesFromLogicalDepsJSON(ldj)
		pkgs = append(pkgs, ps...)
		relationships = append(relationships, rs...)
	}
	return pkgs, relationships
}

// packagesFromLogicalDepsJSON converts a logicalDepsJSON (using the new map type) into catalog packages.
func packagesFromLogicalDepsJSON(doc logicalDepsJSON) ([]pkg.Package, []artifact.Relationship) {
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
	for _, nameVersion := range nameVersions {
		name, version := extractNameAndVersion(nameVersion)
		if rootPkg != nil && name == rootPkg.Name && version == rootPkg.Version {
			continue
		}
		lp := doc.PackagesByNameVersion[nameVersion]
		dotnetPkg := newDotnetDepsPackage(lp, doc.Location)
		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[nameVersion] = *dotnetPkg
		}
	}

	return pkgs, relationshipsFromLogicalDepsJSON(doc, pkgMap)
}

// relationshipsFromLogicalDepsJSON creates relationships from a logicalDepsJSON document for only the given syft packages.
// It is possible that the document describes more packages than that is provided as syft packages, in which cases
// those relationships will not be created.
func relationshipsFromLogicalDepsJSON(doc logicalDepsJSON, pkgMap map[string]pkg.Package) []artifact.Relationship {
	var relationships []artifact.Relationship
	for _, lp := range doc.PackagesByNameVersion {
		if lp.Targets == nil {
			continue
		}
		for depName, depVersion := range lp.Targets.Dependencies {
			depNameVersion := createNameAndVersion(depName, depVersion)
			depPkg, ok := pkgMap[depNameVersion]
			if !ok {
				continue
			}
			thisPkg, ok := pkgMap[lp.NameVersion]
			if !ok {
				continue
			}
			rel := artifact.Relationship{
				From: depPkg,
				To:   thisPkg,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rel)
		}
	}

	relationship.Sort(relationships)
	return relationships
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
func findPEFiles(resolver file.Resolver) ([]logicalDotnetPE, error, error) {
	peLocs, err := resolver.FilesByGlob(dllGlob, exeGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find PE files: %w", err)
	}

	var peFiles []logicalDotnetPE
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
func readPEFile(resolver file.Resolver, loc file.Location) (*logicalDotnetPE, error) {
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
