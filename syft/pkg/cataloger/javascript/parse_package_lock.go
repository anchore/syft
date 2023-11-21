package javascript

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parsePackageLock

// packageLock represents a JavaScript package.lock json file
type packageLock struct {
	Name            string                            `json:"name"`
	Version         string                            `json:"version"`
	LockfileVersion int                               `json:"lockfileVersion"`
	Dependencies    map[string]*packageLockDependency `json:"dependencies"`
	Packages        map[string]*packageLockPackage    `json:"packages"`
	Requires        bool                              `json:"requires"`
}

type packageLockPackage struct {
	Name                 string             `json:"name"`
	Version              string             `json:"version"`
	Integrity            string             `json:"integrity"`
	Resolved             string             `json:"resolved"`
	Dependencies         map[string]string  `json:"dependencies"`
	Workspaces           []string           `json:"workspaces"`
	OptionalDependencies map[string]string  `json:"optionalDependencies"`
	DevDependencies      map[string]string  `json:"devDependencies"`
	Link                 bool               `json:"link"`
	License              packageLockLicense `json:"license"`
	Dev                  bool               `json:"dev"`
	Peer                 bool               `json:"peer"`
	Requires             map[string]string  `json:"requires"`
}

type packageLockDependency struct {
	name         string
	Version      string                            `json:"version"`
	Requires     map[string]string                 `json:"requires"`
	Integrity    string                            `json:"integrity"`
	Resolved     string                            `json:"resolved"`
	Dev          bool                              `json:"dev"`
	Dependencies map[string]*packageLockDependency `json:"dependencies"`
}

// packageLockLicense
type packageLockLicense []string

func parsePackageLockFile(reader file.LocationReadCloser) (packageLock, error) {
	// in the case we find package-lock.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(reader.Path()) {
		return packageLock{}, nil
	}
	dec := json.NewDecoder(reader)

	var lock packageLock
	for {
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return packageLock{}, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
	}
	return lock, nil
}

// parsePackageLock parses a package-lock.json and returns the discovered JavaScript packages.
func parsePackageLock(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]syftPkg.Package, []artifact.Relationship, error) {
	lock, err := parsePackageLockFile(reader)
	if err != nil {
		return nil, nil, err
	}
	pkgs, rels := finalizePackageLockWithoutPackageJSON(resolver, &lock, reader.Location)
	return pkgs, rels, nil
}

func finalizePackageLockWithoutPackageJSON(resolver file.Resolver, pkglock *packageLock, indexLocation file.Location) ([]syftPkg.Package, []artifact.Relationship) {
	var root syftPkg.Package
	if pkglock.Name == "" {
		name := rootNameFromPath(indexLocation)
		p := packageLockPackage{Name: name, Version: "0.0.0"}
		root = newPackageLockV2Package(
			resolver,
			indexLocation,
			name,
			p,
		)
	} else {
		p := packageLockPackage{Name: pkglock.Name, Version: pkglock.Version}
		root = newPackageLockV2Package(
			resolver,
			indexLocation,
			pkglock.Name,
			p,
		)
	}

	if pkglock.LockfileVersion == 1 {
		return finalizePackageLockWithoutPackageJSONV1(resolver, pkglock, indexLocation, root)
	}

	if pkglock.LockfileVersion == 3 || pkglock.LockfileVersion == 2 {
		root = newPackageLockV2Package(
			resolver,
			indexLocation,
			pkglock.Name,
			*pkglock.Packages[""],
		)
		return finalizePackageLockV2(resolver, pkglock, indexLocation, root)
	}

	return nil, nil
}

func finalizePackageLockWithPackageJSON(resolver file.Resolver, pkgjson *packageJSON, pkglock *packageLock, indexLocation file.Location) ([]syftPkg.Package, []artifact.Relationship) {
	if pkgjson == nil {
		return finalizePackageLockWithoutPackageJSON(resolver, pkglock, indexLocation)
	}

	if !pkgjson.hasNameAndVersionValues() {
		log.Debugf("encountered package.json file without a name and/or version field, ignoring (path=%q)", indexLocation.Path())
		return nil, nil
	}

	p := packageLockPackage{Name: pkgjson.Name, Version: pkgjson.Version}
	root := newPackageLockV2Package(
		resolver,
		indexLocation,
		pkglock.Name,
		p,
	)

	if pkglock.LockfileVersion == 1 {
		return finalizePackageLockWithPackageJSONV1(resolver, pkgjson, pkglock, indexLocation, root)
	}

	if pkglock.LockfileVersion == 3 || pkglock.LockfileVersion == 2 {
		return finalizePackageLockV2(resolver, pkglock, indexLocation, root)
	}

	return nil, nil
}

func finalizePackageLockWithoutPackageJSONV1(resolver file.Resolver, pkglock *packageLock, indexLocation file.Location, root syftPkg.Package) ([]syftPkg.Package, []artifact.Relationship) {
	if pkglock.LockfileVersion != 1 {
		return nil, nil
	}
	pkgs := []syftPkg.Package{}
	pkgs = append(pkgs, root)

	// create packages
	for name, lockDep := range pkglock.Dependencies {
		lockDep.name = name
		pkg := newPackageLockV1Package(
			resolver,
			indexLocation,
			name,
			*lockDep,
		)
		pkgs = append(pkgs, pkg)
	}
	syftPkg.Sort(pkgs)
	return pkgs, nil
}

func finalizePackageLockWithPackageJSONV1(resolver file.Resolver, pkgjson *packageJSON, pkglock *packageLock, indexLocation file.Location, root syftPkg.Package) ([]syftPkg.Package, []artifact.Relationship) {
	if pkglock.LockfileVersion != 1 {
		return nil, nil
	}
	pkgs := []syftPkg.Package{}
	relationships := []artifact.Relationship{}

	pkgs = append(pkgs, root)
	depnameMap := map[string]syftPkg.Package{}

	// create packages
	for name, lockDep := range pkglock.Dependencies {
		lockDep.name = name
		pkg := newPackageLockV1Package(
			resolver,
			indexLocation,
			name,
			*lockDep,
		)
		pkgs = append(pkgs, pkg)
		depnameMap[name] = pkg
	}

	// create relationships
	for name, lockDep := range pkglock.Dependencies {
		lockDep.name = name
		for name, sub := range lockDep.Dependencies {
			sub.name = name
			if subPkg, ok := depnameMap[name]; ok {
				rel := artifact.Relationship{
					From: subPkg,
					To:   depnameMap[name],
					Type: artifact.DependencyOfRelationship,
				}
				relationships = append(relationships, rel)
			}
		}
		for name := range lockDep.Requires {
			if subPkg, ok := depnameMap[name]; ok {
				rel := artifact.Relationship{
					From: subPkg,
					To:   depnameMap[name],
					Type: artifact.DependencyOfRelationship,
				}
				relationships = append(relationships, rel)
			}
		}
	}

	for name := range pkgjson.Dependencies {
		rel := artifact.Relationship{
			From: depnameMap[name],
			To:   root,
			Type: artifact.DependencyOfRelationship,
		}
		relationships = append(relationships, rel)
	}

	for name := range pkgjson.DevDependencies {
		rel := artifact.Relationship{
			From: depnameMap[name],
			To:   root,
			Type: artifact.DependencyOfRelationship,
		}
		relationships = append(relationships, rel)
	}

	syftPkg.Sort(pkgs)
	syftPkg.SortRelationships(relationships)
	return pkgs, relationships
}

//nolint:funlen
func finalizePackageLockV2(resolver file.Resolver, pkglock *packageLock, indexLocation file.Location, root syftPkg.Package) ([]syftPkg.Package, []artifact.Relationship) {
	if pkglock.LockfileVersion != 3 && pkglock.LockfileVersion != 2 {
		return nil, nil
	}
	if _, ok := pkglock.Packages[""]; !ok {
		log.Debugf("encountered a package-lock.json file without a root pakcage, ignoring (path=%q)", indexLocation.Path())
		return nil, nil
	}

	pkgs := []syftPkg.Package{}
	pkgs = append(pkgs, root)
	relationships := []artifact.Relationship{}
	packages := pkglock.Packages
	pkgMap := map[artifact.ID]syftPkg.Package{}

	// Resolve links first
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json#packages
	resolveLinks(packages)

	// directDeps := map[string]struct{}{}
	for name, version := range lo.Assign(packages[""].Dependencies, packages[""].OptionalDependencies, packages[""].DevDependencies) {
		pkgPath := joinPaths(nodeModulesDir, name)
		if _, ok := packages[pkgPath]; !ok {
			log.Debugf("Unable to find the direct dependency: '%s@%s'", name, version)
			continue
		}
		// Store the package paths of direct dependencies
		// e.g. node_modules/body-parser
		// directDeps[pkgPath] = struct{}{}

		p := newPackageLockV2Package(
			resolver,
			indexLocation,
			name,
			*packages[pkgPath],
		)
		pkgMap[p.ID()] = p
		pkgs = append(pkgs, p)

		relationships = append(relationships, artifact.Relationship{
			From: p,
			To:   root,
			Type: artifact.DependencyOfRelationship,
		})
	}

	for pkgPath, pkg := range packages {
		if !strings.HasPrefix(pkgPath, "node_modules") {
			continue
		}

		// skip peer dependencies
		if pkg.Peer {
			continue
		}

		// pkg.Name exists when package name != folder name
		pkgName := pkg.Name
		if pkgName == "" {
			pkgName = pkgNameFromPath(pkgPath)
		}

		p := newPackageLockV2Package(
			resolver,
			indexLocation,
			pkgName,
			*pkg,
		)
		// add only if not already added
		if _, ok := pkgMap[p.ID()]; !ok {
			pkgs = append(pkgs, p)
		}

		// npm builds graph using optional deps. e.g.:
		// └─┬ watchpack@1.7.5
		// ├─┬ chokidar@3.5.3 - optional dependency
		// │ └── glob-parent@5.1.
		dependencies := lo.Assign(pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies)
		// dependsOn := make([]string, 0, len(dependencies))
		for depName, depVersion := range dependencies {
			dep, err := findDependsOn(pkgPath, depName, packages)
			if err != nil {
				log.Warnf("Cannot resolve the version: '%s@%s'", depName, depVersion)
				continue
			}

			depPkg := newPackageLockV2Package(
				resolver,
				indexLocation,
				depName,
				*dep,
			)

			relationships = append(relationships, artifact.Relationship{
				From: depPkg,
				To:   p,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	syftPkg.Sort(pkgs)
	syftPkg.SortRelationships(relationships)
	return pkgs, relationships
}

func (licenses *packageLockLicense) UnmarshalJSON(data []byte) (err error) {
	// The license field could be either a string or an array.

	// 1. An array
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*licenses = arr
		return nil
	}

	// 2. A string
	var str string
	if err = json.Unmarshal(data, &str); err == nil {
		*licenses = make([]string, 1)
		(*licenses)[0] = str
		return nil
	}

	// debug the content we did not expect
	if len(data) > 0 {
		log.WithFields("license", string(data)).Debug("Unable to parse the following `license` value in package-lock.json")
	}

	// 3. Unexpected
	// In case we are unable to parse the license field,
	// i.e if we have not covered the full specification,
	// we do not want to throw an error, instead assign nil.
	return nil
}

// for local package npm uses links. e.g.:
// function/func1 -> target of package
// node_modules/func1 -> link to target
// see `package-lock_v3_with_workspace.json` to better understanding
func resolveLinks(packages map[string]*packageLockPackage) {
	links := lo.PickBy(packages, func(_ string, pkg *packageLockPackage) bool {
		return pkg.Link
	})

	// Early return
	if len(links) == 0 {
		return
	}

	rootPkg := packages[""]
	if rootPkg.Dependencies == nil {
		rootPkg.Dependencies = make(map[string]string)
	}

	workspaces := rootPkg.Workspaces
	for pkgPath, pkg := range packages {
		for linkPath, link := range links {
			if !strings.HasPrefix(pkgPath, link.Resolved) {
				continue
			}
			// The target doesn't have the "resolved" field, so we need to copy it from the link.
			if pkg.Resolved == "" {
				pkg.Resolved = link.Resolved
			}

			// Resolve the link package so all packages are located under "node_modules".
			resolvedPath := strings.ReplaceAll(pkgPath, link.Resolved, linkPath)
			packages[resolvedPath] = pkg

			// Delete the target package
			delete(packages, pkgPath)

			if isWorkspace(pkgPath, workspaces) {
				rootPkg.Dependencies[pkgNameFromPath(linkPath)] = pkg.Version
			}
			break
		}
	}
	packages[""] = rootPkg
}

const nodeModulesDir = "node_modules"

func pkgNameFromPath(path string) string {
	// lock file contains path to dependency in `node_modules`. e.g.:
	// node_modules/string-width
	// node_modules/string-width/node_modules/strip-ansi
	// we renamed to `node_modules` directory prefixes `workspace` when resolving Links
	// node_modules/function1
	// node_modules/nested_func/node_modules/debug
	if index := strings.LastIndex(path, nodeModulesDir); index != -1 {
		return path[index+len(nodeModulesDir)+1:]
	}
	log.Warnf("npm %q package path doesn't have `node_modules` prefix", path)
	return path
}

func isWorkspace(pkgPath string, workspaces []string) bool {
	for _, workspace := range workspaces {
		if match, err := path.Match(workspace, pkgPath); err != nil {
			log.Debugf("unable to parse workspace %q for %s", workspace, pkgPath)
		} else if match {
			return true
		}
	}
	return false
}

func joinPaths(paths ...string) string {
	return strings.Join(paths, "/")
}

func findDependsOn(pkgPath, depName string, packages map[string]*packageLockPackage) (*packageLockPackage, error) {
	depPath := joinPaths(pkgPath, nodeModulesDir)
	paths := strings.Split(depPath, "/")
	// Try to resolve the version with the nearest directory
	// e.g. for pkgPath == `node_modules/body-parser/node_modules/debug`, depName == `ms`:
	//    - "node_modules/body-parser/node_modules/debug/node_modules/ms"
	//    - "node_modules/body-parser/node_modules/ms"
	//    - "node_modules/ms"
	for i := len(paths) - 1; i >= 0; i-- {
		if paths[i] != nodeModulesDir {
			continue
		}
		path := joinPaths(paths[:i+1]...)
		path = joinPaths(path, depName)

		if dep, ok := packages[path]; ok {
			return dep, nil
		}
	}

	// It should not reach here.
	return nil, xerrors.Errorf("can't find dependsOn for %s", depName)
}
