package javascript

import (
	"path"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/filter"
)

var _ generic.GroupedParser = parseJavaScript

var path2dir = func(relpath string) string { return path.Dir(strings.ReplaceAll(relpath, `\`, `/`)) }

func parseJavaScript(resolver file.Resolver, e *generic.Environment, readers []file.LocationReadCloser) (pkgs []pkg.Package, relationships []artifact.Relationship, err error) {
	jsonMap := map[string]*packageJSON{}
	lockMap := map[string]*packageLock{}
	yarnMap := map[string]map[string]*yarnLockPackage{}
	pnpmMap := map[string]map[string]*pnpmLockPackage{}
	pnpmLock := map[string]pnpmLockYaml{}
	pnpmLocation := file.Location{}
	yarnLocation := file.Location{}
	lockLocation := file.Location{}

	for _, reader := range readers {
		// in the case we find matching files in the node_modules directories, skip those
		// as the whole purpose of the lock file is for the specific dependencies of the root project
		if pathContainsNodeModulesDirectory(reader.AccessPath()) {
			return nil, nil, nil
		}

		path := reader.Location.RealPath
		if filter.JavaScriptYarnLock(path) {
			yarnMap[path2dir(path)] = parseYarnLockFile(resolver, reader)
			yarnLocation = reader.Location
		}
		if filter.JavaScriptPackageJSON(path) {
			js, err := parsePackageJSONFile(resolver, e, reader)
			if err != nil {
				return nil, nil, err
			}
			js.File = path
			jsonMap[js.Name] = js
		}
		if filter.JavaScriptPackageLock(path) {
			lock, err := parsePackageLockFile(reader)
			if err != nil {
				return nil, nil, err
			}
			lockMap[lock.Name] = &lock
			lockLocation = reader.Location
		}
		if filter.JavaScriptPmpmLock(path) {
			pMap, pLock := parsePnpmLockFile(reader)
			pnpmMap[path2dir(path)] = pMap
			pnpmLock[path2dir(path)] = pLock
			pnpmLocation = reader.Location
		}
	}

	for name, js := range jsonMap {
		if lock, ok := lockMap[name]; ok {
			p, rels := finalizePackageLockWithPackageJSON(resolver, js, lock, lockLocation)
			pkgs = append(pkgs, p...)
			relationships = append(relationships, rels...)
		}

		if js.File != "" {
			if yarn, ok := yarnMap[path2dir(js.File)]; ok {
				p, rels := finalizeYarnLockWithPackageJSON(resolver, js, yarn, yarnLocation)
				pkgs = append(pkgs, p...)
				relationships = append(relationships, rels...)
			}
			if pnpm, ok := pnpmMap[path2dir(js.File)]; ok {
				pLock := pnpmLock[path2dir(js.File)]
				p, rels := finalizePnpmLockWithPackageJSON(resolver, js, &pLock, pnpm, pnpmLocation)
				pkgs = append(pkgs, p...)
				relationships = append(relationships, rels...)
			}
		}
	}

	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
	return pkgs, relationships, nil
}
