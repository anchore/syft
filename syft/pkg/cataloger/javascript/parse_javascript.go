package javascript

import (
	"fmt"
	"path"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/filter"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/model"
)

// var _ generic.Parser = parseJavascript

func _depSet() *model.DepGraphNodeMap {
	return model.NewDepGraphNodeMap(func(s ...string) string {
		return fmt.Sprintf("%s:%s", s[0], s[1])
	}, func(s ...string) *model.DepGraphNode {
		return &model.DepGraphNode{
			Name:      s[0],
			Version:   s[1],
			Integrity: s[2],
			Resolved:  s[3],
			Licenses:  strings.Split(s[4], ","),
		}
	})
}

func processJavascriptFiles(
	readers []file.LocationReadCloser,
	resolver file.Resolver,
	jsonMap map[string]*packageJSON,
	jsonLocation file.Location,
	lockMap map[string]*packageLock,
	lockLocation file.Location,
	pnpmMap map[string]map[string]*pnpmLockPackage,
	pnpmLocation file.Location,
	yarnMap map[string]map[string]*yarnLockPackage,
	yarnLocation file.Location,
) ([]pkg.Package, []artifact.Relationship) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	if len(readers) == 1 {
		for _, js := range jsonMap {
			p, _ := parsePackageJSONWithLock(resolver, js, nil, jsonLocation)
			pkgs = append(pkgs, p...)
		}
		for _, l := range lockMap {
			p, _ := parsePackageJSONWithLock(resolver, nil, l, lockLocation)
			pkgs = append(pkgs, p...)
		}
		for _, yl := range yarnMap {
			p, _ := parsePackageJSONWithYarnLock(resolver, nil, yl, yarnLocation)
			pkgs = append(pkgs, p...)
		}
		for _, pl := range pnpmMap {
			p, _ := parsePackageJSONWithPnpmLock(resolver, nil, pl, pnpmLocation)
			pkgs = append(pkgs, p...)
		}
	} else {
		for name, js := range jsonMap {
			if lock, ok := lockMap[name]; ok {
				p, rels := parsePackageJSONWithLock(resolver, js, lock, lockLocation)
				pkgs = append(pkgs, p...)
				relationships = append(relationships, rels...)
			}

			if js.File != "" {
				if yarn, ok := yarnMap[path2dir(js.File)]; ok {
					p, rels := parsePackageJSONWithYarnLock(resolver, js, yarn, yarnLocation)
					pkgs = append(pkgs, p...)
					relationships = append(relationships, rels...)
				}
				if pnpm, ok := pnpmMap[path2dir(js.File)]; ok {
					p, rels := parsePackageJSONWithPnpmLock(resolver, js, pnpm, pnpmLocation)
					pkgs = append(pkgs, p...)
					relationships = append(relationships, rels...)
				}
			}
		}
	}
	return pkgs, relationships
}

var path2dir = func(relpath string) string { return path.Dir(strings.ReplaceAll(relpath, `\`, `/`)) }

func parseJavascript(resolver file.Resolver, e *generic.Environment, readers []file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	jsonMap := map[string]*packageJSON{}
	lockMap := map[string]*packageLock{}
	yarnMap := map[string]map[string]*yarnLockPackage{}
	pnpmMap := map[string]map[string]*pnpmLockPackage{}
	pnpmLocation := file.Location{}
	yarnLocation := file.Location{}
	jsonLocation := file.Location{}
	lockLocation := file.Location{}

	for _, reader := range readers {
		// in the case we find matching files in the node_modules directories, skip those
		// as the whole purpose of the lock file is for the specific dependencies of the root project
		if pathContainsNodeModulesDirectory(reader.AccessPath()) {
			return nil, nil, nil
		}

		path := reader.Location.RealPath
		if filter.JavaScriptYarnLock(path) {
			yarnMap[path2dir(path)] = parseYarnLockFile(reader)
			yarnLocation = reader.Location
		}
		if filter.JavaScriptPackageJSON(path) {
			js, err := parsePackageJSONFile(resolver, e, reader)
			if err != nil {
				return nil, nil, err
			}
			js.File = path
			jsonMap[js.Name] = js
			jsonLocation = reader.Location
		}
		if filter.JavaScriptPackageLock(path) {
			lock, err := parsePackageLockFile(reader)
			if err != nil {
				return nil, nil, err
			}
			lockMap[lock.Name] = &lock
			lockLocation = reader.Location
		}
		if filter.JavascriptPmpmLock(path) {
			pnpmMap[path2dir(path)] = parsePnpmLockFile(reader)
			pnpmLocation = reader.Location
		}
	}

	pkgs, relationships := processJavascriptFiles(
		readers,
		resolver,
		jsonMap,
		jsonLocation,
		lockMap,
		lockLocation,
		pnpmMap,
		pnpmLocation,
		yarnMap,
		yarnLocation,
	)

	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
	return pkgs, relationships, nil
}
