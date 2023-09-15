package javascript

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/filter"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/key"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/model"
)

func _depSet() *model.DepGraphNodeMap {
	return model.NewDepGraphNodeMap(func(s ...string) string {
		return fmt.Sprintf("%s:%s", s[0], s[1])
	}, func(s ...string) *model.DepGraphNode {
		return &model.DepGraphNode{
			Name:      s[0],
			Version:   s[1],
			Integrity: s[2],
			Resolved:  s[3],
		}
	})
}

func convertToPkgAndRelationships(resolver file.Resolver, location file.Location, root []*model.DepGraphNode) ([]pkg.Package, []artifact.Relationship) {
	var packages []pkg.Package
	var relationships []artifact.Relationship
	pkgSet := map[string]bool{}

	processNode := func(parent, node *model.DepGraphNode) bool {
		locations := file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		p := finalizeLockPkg(
			resolver,
			location,
			pkg.Package{
				Name:         node.Name,
				Version:      node.Version,
				Locations:    locations,
				PURL:         packageURL(node.Name, node.Version),
				Language:     pkg.JavaScript,
				Type:         pkg.NpmPkg,
				MetadataType: pkg.NpmPackageLockJSONMetadataType,
				Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: node.Resolved, Integrity: node.Integrity},
			},
		)

		if !pkgSet[key.NpmPackageKey(p.Name, p.Version)] {
			packages = append(packages, p)
			pkgSet[key.NpmPackageKey(p.Name, p.Version)] = true
		}

		if parent != nil {
			parentPkg := finalizeLockPkg(
				resolver,
				location,
				pkg.Package{
					Name:         parent.Name,
					Version:      parent.Version,
					Locations:    locations,
					PURL:         packageURL(parent.Name, parent.Version),
					Language:     pkg.JavaScript,
					Type:         pkg.NpmPkg,
					MetadataType: pkg.NpmPackageLockJSONMetadataType,
					Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: parent.Resolved, Integrity: parent.Integrity},
				})
			rel := artifact.Relationship{
				From: parentPkg,
				To:   p,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rel)
		}
		return true
	}

	for _, rootNode := range root {
		rootNode.ForEachPath(processNode)
	}

	return packages, relationships
}

func parseJavascript(resolver file.Resolver, e *generic.Environment, readers []file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var root []*model.DepGraphNode

	jsonMap := map[string]*packageJSON{}
	lockMap := map[string]*packageLock{}
	yarnMap := map[string]map[string]*yarnLockPackage{}
	pnpmMap := map[string]map[string]*pnpmLockPackage{}

	path2dir := func(relpath string) string { return path.Dir(strings.ReplaceAll(relpath, `\`, `/`)) }
	var fileLocation file.Location

	for _, reader := range readers {
		// in the case we find matching files in the node_modules directories, skip those
		// as the whole purpose of the lock file is for the specific dependencies of the root project
		if pathContainsNodeModulesDirectory(reader.AccessPath()) {
			return nil, nil, nil
		}

		path := reader.Location.RealPath
		if filter.JavaScriptYarnLock(path) {
			yarnMap[path2dir(path)] = parseYarnLockFile(reader)
			fileLocation = reader.Location
		}
		if filter.JavaScriptPackageJson(path) {
			var js *packageJSON
			decoder := json.NewDecoder(reader)
			err := decoder.Decode(&js)
			if err != nil {
				return nil, nil, err
			}
			js.File = path
			jsonMap[js.Name] = js
		}
		if filter.JavaScriptPackageLock(path) {
			var lock *packageLock
			decoder := json.NewDecoder(reader)
			err := decoder.Decode(&lock)
			if err != nil {
				return nil, nil, err
			}
			lockMap[lock.Name] = lock
			fileLocation = reader.Location
		}
		if filter.JavascriptPmpmLock(path) {
			pnpmMap[path2dir(path)] = parsePnpmLockFile(reader)
			fileLocation = reader.Location
		}
	}

	for name, js := range jsonMap {
		if lock, ok := lockMap[name]; ok {
			root = append(root, parsePackageJsonWithLock(js, lock))
		}

		if js.File != "" {
			if yarn, ok := yarnMap[path2dir(js.File)]; ok {
				root = append(root, parsePackageJsonWithYarnLock(js, yarn))
			}
			if pnpm, ok := pnpmMap[path2dir(js.File)]; ok {
				root = append(root, ParsePackageJsonWithPnpmLock(js, pnpm))
			}
		}
	}

	pkgs, relationships := convertToPkgAndRelationships(resolver, fileLocation, root)
	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
	return pkgs, relationships, nil
}
