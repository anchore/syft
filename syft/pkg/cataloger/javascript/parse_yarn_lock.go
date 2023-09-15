package javascript

import (
	"bufio"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/key"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/model"
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
	// in the case we find yarn.lock files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the project
	if pathContainsNodeModulesDirectory(reader.AccessPath()) {
		return nil, nil, nil
	}

	seenPkgs := map[string]bool{}
	var pkgs []pkg.Package

	lock := parseYarnLockFile(reader)
	for _, pkg := range lock {
		key := key.NpmPackageKey(pkg.Name, pkg.Version)
		if !seenPkgs[key] {
			pkgs = append(pkgs, newYarnLockPackage(resolver, reader.Location, pkg.Name, pkg.Version))
			seenPkgs[key] = true
		}
	}

	pkg.Sort(pkgs)
	return pkgs, nil, nil
}

// parseYarnLockFile takes a yarn.lock file and returns a map of packages
func parseYarnLockFile(file file.LocationReadCloser) map[string]*yarnLockPackage {
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
	lock := map[string]*yarnLockPackage{}

	scanner := bufio.NewScanner(file.ReadCloser)
	scanner.Split(yarnparse.ScanBlocks)
	for scanner.Scan() {
		block := scanner.Bytes()
		pkg, refVersions, newLine, err := parseBlock(block, lineNumber)
		lineNumber = newLine + 2
		if err != nil {
			return nil
		} else if pkg.Name == "" {
			continue
		}

		for _, refVersion := range refVersions {
			lock[refVersion] = &pkg
		}
	}

	if err := scanner.Err(); err != nil {
		return nil
	}

	return lock
}

// parsePackageJSONWithYarnLock takes a package.json and yarn.lock package representation
// and returns a DepGraphNode tree of packages and their dependencies
func parsePackageJSONWithYarnLock(pkgjson *packageJSON, yarnlock map[string]*yarnLockPackage) *model.DepGraphNode {
	root := &model.DepGraphNode{Name: pkgjson.Name, Version: pkgjson.Version, Path: pkgjson.File}
	_dep := _depSet().LoadOrStore

	for _, lock := range yarnlock {
		dep := _dep(
			lock.Name,
			lock.Version,
			lock.Integrity,
			lock.Resolved,
		)
		for name, version := range lock.Dependencies {
			sub := yarnlock[key.NpmPackageKey(name, version)]
			if sub != nil {
				dep.AppendChild(_dep(
					sub.Name,
					sub.Version,
					sub.Integrity,
					sub.Resolved,
				))
			}
		}
		root.AppendChild(dep)
	}

	for name, version := range pkgjson.DevDependencies {
		lock := yarnlock[key.NpmPackageKey(name, version)]
		if lock != nil {
			dep := _dep(
				lock.Name,
				lock.Version,
				lock.Integrity,
				lock.Resolved,
			)
			dep.Develop = true
			root.AppendChild(dep)
		} else {
			root.AppendChild(&model.DepGraphNode{
				Name:      name,
				Version:   version,
				Develop:   true,
				Integrity: "",
				Resolved:  "",
			})
		}
	}

	return root
}

func parseBlock(block []byte, lineNum int) (pkg yarnLockPackage, refVersions []string, newLine int, err error) {
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
