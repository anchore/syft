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

func (c depsBinaryCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) { //nolint:funlen
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

	var roots []*pkg.Package
	for _, docs := range depDocGroups {
		for _, doc := range docs {
			rts, ps, rs := packagesFromLogicalDepsJSON(doc, c.config)
			if rts != nil {
				roots = append(roots, rts)
			}
			pkgs = append(pkgs, ps...)
			relationships = append(relationships, rs...)
		}
	}

	// track existing runtime packages so we don't create duplicates
	existingRuntimeVersions := strset.New()
	var runtimePkgs []*pkg.Package
	for i := range pkgs {
		p := &pkgs[i]
		if p.Type != pkg.DotnetPkg {
			continue
		}
		if isRuntime(p.Name) {
			existingRuntimeVersions.Add(p.Version)
			runtimePkgs = append(runtimePkgs, p)
		}
	}

	runtimes := make(map[string][]file.Location)
	for _, pe := range remainingPeFiles {
		runtimeVer, isRuntimePkg := isRuntimePackageLocation(pe.Location)
		if isRuntimePkg {
			runtimes[runtimeVer] = append(runtimes[runtimeVer], pe.Location)
			// we should never catalog runtime DLLs as packages themselves, instead there should be a single logical package
			continue
		}
		pkgs = append(pkgs, newDotnetBinaryPackage(pe.VersionResources, pe.Location))
	}

	// if we found any runtime DLLs we ignored, then make packages for each version found
	for version, locs := range runtimes {
		if len(locs) == 0 || existingRuntimeVersions.Has(version) {
			continue
		}
		rtp := pkg.Package{
			Name:      "Microsoft.NETCore.App",
			Version:   version,
			Type:      pkg.DotnetPkg,
			CPEs:      runtimeCPEs(version),
			Locations: file.NewLocationSet(locs...),
		}
		pkgs = append(pkgs, rtp)
		runtimePkgs = append(runtimePkgs, &rtp)
	}

	// create a relationship from every runtime package to every root package...
	for _, root := range roots {
		for _, runtimePkg := range runtimePkgs {
			relationships = append(relationships, artifact.Relationship{
				From: *runtimePkg,
				To:   *root,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	// in the process of creating root-to-runtime relationships, we may have created duplicate relationships. Use the relationship index to deduplicate.
	return pkgs, relationship.NewIndex(relationships...).All(), unknowns
}

var runtimeDLLPathPattern = regexp.MustCompile(`/Microsoft\.NETCore\.App/(?P<version>\d+\.\d+\.\d+)/[^/]+\.dll`)

func isRuntimePackageLocation(loc file.Location) (string, bool) {
	// we should look at the realpath to see if it is a "**/Microsoft.NETCore.App/\d+.\d+.\d+/*.dll"
	// and if so treat it as a runtime package
	if match := runtimeDLLPathPattern.FindStringSubmatch(loc.RealPath); match != nil {
		versionIndex := runtimeDLLPathPattern.SubexpIndex("version")
		if versionIndex != -1 {
			version := match[versionIndex]
			return version, true
		}
	}

	return "", false
}

// partitionPEs pairs PE files with the deps.json based on directory containment.
func partitionPEs(depJsons []logicalDepsJSON, peFiles []logicalPE) ([]logicalDepsJSON, []logicalPE, []logicalDepsJSON) {
	// sort deps.json paths from longest to shortest. This is so we are processing the most specific match first.
	sort.Slice(depJsons, func(i, j int) bool {
		return depJsons[i].Location.RealPath > depJsons[j].Location.RealPath
	})

	// we should be processing PE files in a stable order
	sort.Slice(peFiles, func(i, j int) bool {
		return peFiles[i].Location.RealPath > peFiles[j].Location.RealPath
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
			continue
		}

		if targetPath, ok := p.CompilePathsByRelativeDLLPath[relativeDllPath]; ok {
			pe.TargetPath = targetPath
			p.Executables = append(p.Executables, pe)
			dep.PackagesByNameVersion[key] = p // update the map with the modified package
			found = true
			continue
		}

		if p.NativePaths.Has(relativeDllPath) {
			pe.TargetPath = relativeDllPath
			p.Executables = append(p.Executables, pe)
			dep.PackagesByNameVersion[key] = p // update the map with the modified package
			found = true
			continue
		}
	}
	return found
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
		_, ps, rs := packagesFromLogicalDepsJSON(ldj, config)
		pkgs = append(pkgs, ps...)
		relationships = append(relationships, rs...)
	}
	return pkgs, relationships
}

// packagesFromLogicalDepsJSON converts a logicalDepsJSON (using the new map type) into catalog packages.
func packagesFromLogicalDepsJSON(doc logicalDepsJSON, config CatalogerConfig) (*pkg.Package, []pkg.Package, []artifact.Relationship) {
	var rootPkg *pkg.Package
	if rootLpkg, hasRoot := doc.RootPackage(); hasRoot {
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
		if config.DepPackagesMustHaveDLL && !lp.FoundDLLs(config.PropagateDLLClaimsToParents) {
			// could not find a paired DLL and the user required this...
			skippedDepPkgs[nameVersion] = lp
			continue
		}

		// check to see if we should skip this package because it does not claim a DLL (or has not dependency that claims a DLL)
		if config.DepPackagesMustClaimDLL && !lp.ClaimsDLLs(config.PropagateDLLClaimsToParents) {
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
	rels := relationshipsFromLogicalDepsJSON(doc, pkgMap, skippedDepPkgs)

	// ensure that any libman packages are associated with the all root packages
	for _, libmanPkg := range doc.LibmanPackages {
		pkgs = append(pkgs, libmanPkg)
		if rootPkg == nil {
			continue
		}
		rels = append(rels, artifact.Relationship{
			From: libmanPkg,
			To:   *rootPkg,
			Type: artifact.DependencyOfRelationship,
		})
	}

	return rootPkg, pkgs, rels
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
		for _, depNameVersion := range lp.dependencyNameVersions() {
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
				// Take note that the skipped dependency's dependency could also be skipped, so we need to
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

	for _, depNameVersion := range skippedDep.dependencyNameVersions() {
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

		libman, err := findLibmanJSON(resolver, loc)
		if err != nil {
			unknownErr = unknown.Append(unknownErr, loc, err)
			libman = nil
		}

		depsJSONs = append(depsJSONs, getLogicalDepsJSON(*dj, libman))
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
