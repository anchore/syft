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

func parseYarnLock(resolver file.Resolver, e *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	readers := []file.LocationReadCloser{reader}
	pkgs, _, err := parseJavascript(resolver, e, readers)
	if err != nil {
		return nil, nil, err
	}
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

func rootNameFromPath(location file.Location) string {
	splits := strings.Split(location.RealPath, "/")
	if len(splits) < 2 {
		return ""
	}
	return splits[len(splits)-2]
}

// parsePackageJSONWithYarnLock takes a package.json and yarn.lock package representation
// and returns a DepGraphNode tree of packages and their dependencies
func parsePackageJSONWithYarnLock(resolver file.Resolver, pkgjson *packageJSON, yarnlock map[string]*yarnLockPackage, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	var root *model.DepGraphNode
	if pkgjson != nil {
		root = &model.DepGraphNode{Name: pkgjson.Name, Version: pkgjson.Version, Path: pkgjson.File}
	} else {
		name := rootNameFromPath(indexLocation)
		if name == "" {
			return nil, nil
		}
		root = &model.DepGraphNode{Name: name, Version: "0.0.0", Path: indexLocation.RealPath}
	}
	_dep := _depSet().LoadOrStore

	for _, lock := range yarnlock {
		// skip dev dependencies
		if pkgjson != nil {
			if _, ok := pkgjson.DevDependencies[lock.Name]; ok {
				continue
			}
		}

		dep := _dep(
			lock.Name,
			lock.Version,
			lock.Integrity,
			lock.Resolved,
			"", // licenses
		)
		for name, version := range lock.Dependencies {
			// skip dev dependencies
			if pkgjson != nil {
				if _, ok := pkgjson.DevDependencies[name]; ok {
					continue
				}
			}
			sub := yarnlock[key.NpmPackageKey(name, version)]
			if sub != nil {
				dep.AppendChild(_dep(
					sub.Name,
					sub.Version,
					sub.Integrity,
					sub.Resolved,
					"", // licenses
				))
			}
		}
		root.AppendChild(dep)
	}

	pkgs, rels := convertToPkgAndRelationships(
		resolver,
		indexLocation,
		root,
	)
	return pkgs, rels
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
