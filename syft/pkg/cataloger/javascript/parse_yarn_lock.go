package javascript

import (
	"bufio"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/key"
	yarnparse "github.com/anchore/syft/syft/pkg/cataloger/javascript/parser/yarn"
)

// integrity check
var _ generic.Parser = parseYarnLock

type yarnLockPackage struct {
	Name         string
	Version      string
	Integrity    string
	Resolved     string
	Dependencies map[string]string
}

func parseYarnLock(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	yarnMap := parseYarnLockFile(resolver, reader)
	pkgs, _ := finalizeYarnLockWithoutPackageJSON(resolver, yarnMap, reader.Location)
	return pkgs, nil, nil
}

func newYarnLockPackage(resolver file.Resolver, location file.Location, p *yarnLockPackage) pkg.Package {
	if p == nil {
		return pkg.Package{}
	}

	return finalizeLockPkg(
		resolver,
		location,
		pkg.Package{
			Name:         p.Name,
			Version:      p.Version,
			Locations:    file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
			PURL:         packageURL(p.Name, p.Version),
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  p.Resolved,
				Integrity: p.Integrity,
			},
		},
	)
}

// parseYarnLockFile takes a yarn.lock file and returns a map of packages
func parseYarnLockFile(_ file.Resolver, file file.LocationReadCloser) map[string]*yarnLockPackage {
	/*
		name@version[, name@version]:
			version "xxx"
			resolved "xxx"
			integrity "xxx"
			dependencies:
				name "xxx"
				name "xxx"
	*/
	lineNumber := 1
	lockMap := map[string]*yarnLockPackage{}

	scanner := bufio.NewScanner(file.ReadCloser)
	scanner.Split(yarnparse.ScanBlocks)
	for scanner.Scan() {
		block := scanner.Bytes()
		pkg, refVersions, newLine, err := parseYarnPkgBlock(block, lineNumber)
		lineNumber = newLine + 2
		if err != nil {
			return nil
		} else if pkg.Name == "" {
			continue
		}

		for _, refVersion := range refVersions {
			lockMap[refVersion] = &pkg
		}
	}

	if err := scanner.Err(); err != nil {
		return nil
	}

	return lockMap
}

// rootNameFromPath returns a "fake" root name of a package based on it
// directory name. This is used when there is no package.json file
// to create a root package.
func rootNameFromPath(location file.Location) string {
	splits := strings.Split(location.RealPath, "/")
	if len(splits) < 2 {
		return ""
	}
	return splits[len(splits)-2]
}

// finalizeYarnLockWithPackageJSON takes a yarn.lock file and a package.json file and returns a map of packages
// nolint:funlen
func finalizeYarnLockWithPackageJSON(resolver file.Resolver, pkgjson *packageJSON, yarnlock map[string]*yarnLockPackage, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	if pkgjson == nil {
		return nil, nil
	}

	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	var root pkg.Package
	seenPkgMap := make(map[string]bool)

	p := yarnLockPackage{
		Name:    pkgjson.Name,
		Version: pkgjson.Version,
	}
	root = newYarnLockPackage(resolver, indexLocation, &p)

	for name, version := range pkgjson.Dependencies {
		depPkg := yarnlock[key.NpmPackageKey(name, version)]
		dep := newYarnLockPackage(resolver, indexLocation, depPkg)
		rel := artifact.Relationship{
			From: dep,
			To:   root,
			Type: artifact.DependencyOfRelationship,
		}
		relationships = append(relationships, rel)
	}
	for name, version := range pkgjson.DevDependencies {
		depPkg := yarnlock[key.NpmPackageKey(name, version)]
		dep := newYarnLockPackage(resolver, indexLocation, depPkg)
		rel := artifact.Relationship{
			From: dep,
			To:   root,
			Type: artifact.DependencyOfRelationship,
		}
		relationships = append(relationships, rel)
	}
	pkgs = append(pkgs, root)

	// create packages
	for _, lockPkg := range yarnlock {
		if seenPkgMap[key.NpmPackageKey(lockPkg.Name, lockPkg.Version)] {
			continue
		}

		pkg := newYarnLockPackage(resolver, indexLocation, lockPkg)
		pkgs = append(pkgs, pkg)
		seenPkgMap[key.NpmPackageKey(lockPkg.Name, lockPkg.Version)] = true
	}

	// create relationships
	for _, lockPkg := range yarnlock {
		pkg := newYarnLockPackage(resolver, indexLocation, lockPkg)

		for name, version := range lockPkg.Dependencies {
			dep := yarnlock[key.NpmPackageKey(name, version)]
			depPkg := newYarnLockPackage(
				resolver,
				indexLocation,
				dep,
			)

			rel := artifact.Relationship{
				From: depPkg,
				To:   pkg,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rel)
		}
	}

	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
	return pkgs, relationships
}

// finalizeYarnLockWithoutPackageJSON takes a yarn.lock file and returns a map of packages
func finalizeYarnLockWithoutPackageJSON(resolver file.Resolver, yarnlock map[string]*yarnLockPackage, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	seenPkgMap := make(map[string]bool)

	name := rootNameFromPath(indexLocation)
	if name != "" {
		p := yarnLockPackage{
			Name:    name,
			Version: "0.0.0",
		}
		root := newYarnLockPackage(resolver, indexLocation, &p)
		pkgs = append(pkgs, root)
	}

	// create packages
	for _, lockPkg := range yarnlock {
		if seenPkgMap[key.NpmPackageKey(lockPkg.Name, lockPkg.Version)] {
			continue
		}

		pkg := newYarnLockPackage(resolver, indexLocation, lockPkg)
		pkgs = append(pkgs, pkg)
		seenPkgMap[key.NpmPackageKey(lockPkg.Name, lockPkg.Version)] = true
	}

	// create relationships
	for _, lockPkg := range yarnlock {
		pkg := newYarnLockPackage(resolver, indexLocation, lockPkg)

		for name, version := range lockPkg.Dependencies {
			dep := yarnlock[key.NpmPackageKey(name, version)]
			depPkg := newYarnLockPackage(
				resolver,
				indexLocation,
				dep,
			)

			rel := artifact.Relationship{
				From: depPkg,
				To:   pkg,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rel)
		}
	}

	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
	return pkgs, relationships
}

/*
	parseYarnPkgBlock parses a yarn package block like this and return a yarnLockPackage struct
	and refVersions which are "tslib@^2.1.0" and "tslib@^2.3.0" in this example

"tslib@^2.1.0", "tslib@^2.3.0":

	"integrity" "sha512-tGyy4dAjRIEwI7BzsB0lynWgOpfqjUdq91XXAlIWD2OwKBH7oCl/GZG/HT4BOHrTlPMOASlMQ7veyTqpmRcrNA=="
	"resolved" "https://registry.npmjs.org/tslib/-/tslib-2.4.1.tgz"
	"version" "2.4.1"
*/
func parseYarnPkgBlock(block []byte, lineNum int) (pkg yarnLockPackage, refVersions []string, newLine int, err error) {
	pkgRef, lineNumber, err := yarnparse.ParseBlock(block, lineNum)
	for _, pattern := range pkgRef.Patterns {
		nv := strings.Split(pattern, ":")
		if len(nv) != 2 {
			continue
		}
		refVersions = append(refVersions, key.NpmPackageKey(nv[0], nv[1]))
	}

	return yarnLockPackage{
		Name:         pkgRef.Name,
		Version:      pkgRef.Version,
		Integrity:    pkgRef.Integrity,
		Resolved:     pkgRef.Resolved,
		Dependencies: pkgRef.Dependencies,
	}, refVersions, lineNumber, err
}
