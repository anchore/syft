package javascript

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
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
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	Integrity       string             `json:"integrity"`
	Resolved        string             `json:"resolved"`
	Dependencies    map[string]string  `json:"dependencies"`
	DevDependencies map[string]string  `json:"devDependencies"`
	License         packageLockLicense `json:"license"`
	Dev             bool               `json:"dev"`
	Requires        map[string]string  `json:"requires"`
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
	if pathContainsNodeModulesDirectory(reader.AccessPath()) {
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
func parsePackageLock(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	lock, err := parsePackageLockFile(reader)
	if err != nil {
		return nil, nil, err
	}
	pkgs, rels := finalizePackageLockWithoutPackageJSON(resolver, &lock, reader.Location)
	return pkgs, rels, nil
}

func finalizePackageLockWithoutPackageJSON(resolver file.Resolver, pkglock *packageLock, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	var root pkg.Package
	if pkglock.Name == "" {
		name := rootNameFromPath(indexLocation)
		p := packageLockPackage{Name: name, Version: "0.0.0"}
		root = newPackageLockV2Package(resolver, indexLocation, name, p)
	} else {
		p := packageLockPackage{Name: pkglock.Name, Version: pkglock.Version}
		root = newPackageLockV2Package(resolver, indexLocation, pkglock.Name, p)
	}

	if pkglock.LockfileVersion == 1 {
		return finalizePackageLockWithoutPackageJSONV1(resolver, pkglock, indexLocation, root)
	}

	if pkglock.LockfileVersion == 3 || pkglock.LockfileVersion == 2 {
		return finalizePackageLockV2(resolver, pkglock, indexLocation, root)
	}

	return nil, nil
}

func finalizePackageLockWithPackageJSON(resolver file.Resolver, pkgjson *packageJSON, pkglock *packageLock, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	if pkgjson == nil {
		return finalizePackageLockWithoutPackageJSON(resolver, pkglock, indexLocation)
	}

	if !pkgjson.hasNameAndVersionValues() {
		log.Debugf("encountered package.json file without a name and/or version field, ignoring (path=%q)", indexLocation.AccessPath())
		return nil, nil
	}

	p := packageLockPackage{Name: pkgjson.Name, Version: pkgjson.Version}
	root := newPackageLockV2Package(resolver, indexLocation, pkglock.Name, p)

	if pkglock.LockfileVersion == 1 {
		return finalizePackageLockWithPackageJSONV1(resolver, pkgjson, pkglock, indexLocation, root)
	}

	if pkglock.LockfileVersion == 3 || pkglock.LockfileVersion == 2 {
		return finalizePackageLockV2(resolver, pkglock, indexLocation, root)
	}

	return nil, nil
}

func finalizePackageLockWithoutPackageJSONV1(resolver file.Resolver, pkglock *packageLock, indexLocation file.Location, root pkg.Package) ([]pkg.Package, []artifact.Relationship) {
	if pkglock.LockfileVersion != 1 {
		return nil, nil
	}
	pkgs := []pkg.Package{}

	pkgs = append(pkgs, root)
	depnameMap := map[string]pkg.Package{}

	// create packages
	for name, lockDep := range pkglock.Dependencies {
		lockDep.name = name
		pkg := newPackageLockV1Package(resolver, indexLocation, name, *lockDep)
		pkgs = append(pkgs, pkg)
		depnameMap[name] = pkg
	}
	pkg.Sort(pkgs)
	return pkgs, nil
}

func finalizePackageLockWithPackageJSONV1(resolver file.Resolver, pkgjson *packageJSON, pkglock *packageLock, indexLocation file.Location, root pkg.Package) ([]pkg.Package, []artifact.Relationship) {
	if pkglock.LockfileVersion != 1 {
		return nil, nil
	}
	pkgs := []pkg.Package{}
	relationships := []artifact.Relationship{}

	pkgs = append(pkgs, root)
	depnameMap := map[string]pkg.Package{}

	// create packages
	for name, lockDep := range pkglock.Dependencies {
		lockDep.name = name
		pkg := newPackageLockV1Package(resolver, indexLocation, name, *lockDep)
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

	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
	return pkgs, relationships
}

func finalizePackageLockV2(resolver file.Resolver, pkglock *packageLock, indexLocation file.Location, root pkg.Package) ([]pkg.Package, []artifact.Relationship) {
	if pkglock.LockfileVersion != 3 && pkglock.LockfileVersion != 2 {
		return nil, nil
	}

	pkgs := []pkg.Package{}
	relationships := []artifact.Relationship{}
	depnameMap := map[string]pkg.Package{}
	root.Licenses = pkg.NewLicenseSet(pkg.NewLicensesFromLocation(indexLocation, pkglock.Packages[""].License...)...)

	// create packages
	for name, lockDep := range pkglock.Packages {
		// root pkg always equals "" in lock v2/v3
		if name == "" {
			continue
		}

		n := getNameFromPath(name)
		pkg := newPackageLockV2Package(resolver, indexLocation, n, *lockDep)

		pkgs = append(pkgs, pkg)
		// need to store both names
		depnameMap[name] = pkg
		depnameMap[n] = pkg
	}

	// create relationships
	for name, lockDep := range pkglock.Packages {
		// root pkg always equals "" in lock v2/v3
		if name == "" {
			continue
		}

		if dep, ok := depnameMap[name]; ok {
			for childName := range lockDep.Dependencies {
				if childDep, ok := depnameMap[childName]; ok {
					rel := artifact.Relationship{
						From: childDep,
						To:   dep,
						Type: artifact.DependencyOfRelationship,
					}
					relationships = append(relationships, rel)
				}
			}
			rootRel := artifact.Relationship{
				From: dep,
				To:   root,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rootRel)
		}
	}

	pkgs = append(pkgs, root)
	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
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

func getNameFromPath(path string) string {
	parts := strings.Split(path, "node_modules/")
	return parts[len(parts)-1]
}
