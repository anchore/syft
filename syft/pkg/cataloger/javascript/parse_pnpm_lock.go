package javascript

import (
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/key"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/model"
)

// integrity check
var _ generic.Parser = parsePnpmLock

type pnpmLockPackage struct {
	Name         string
	Version      string
	Integrity    string
	Resolved     string
	Dependencies map[string]string
}

type pnpmLockYaml struct {
	Version         string                      `yaml:"lockfileVersion"`
	Specifiers      map[string]interface{}      `yaml:"specifiers"`
	Dependencies    map[string]interface{}      `yaml:"dependencies"`
	DevDependencies map[string]interface{}      `yaml:"devDependencies"`
	Packages        map[string]*pnpmLockPackage `yaml:"packages"`
}

func parsePnpmLock(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	pnpmLock := parsePnpmLockFile(reader)

	for _, lock := range pnpmLock {
		pkgs = append(pkgs, newPnpmPackage(resolver, reader.Location, lock.Name, lock.Version))
	}

	pkg.Sort(pkgs)
	return pkgs, nil, nil
}

// parsePackageJSONWithPnpmLock takes a package.json and pnpm-lock.yaml package representation and returns a DepGraphNode tree
func parsePackageJSONWithPnpmLock(pkgjson *packageJSON, pnpmLock map[string]*pnpmLockPackage) *model.DepGraphNode {
	root := &model.DepGraphNode{Name: pkgjson.Name, Version: pkgjson.Version, Path: pkgjson.File}
	_dep := _depSet().LoadOrStore

	for _, lock := range pnpmLock {
		dep := _dep(
			lock.Name,
			lock.Version,
			"", // integrity
			"", // resolved
		)

		for name, version := range lock.Dependencies {
			sub := pnpmLock[key.NpmPackageKey(name, version)]
			if sub != nil {
				dep.AppendChild(_dep(
					sub.Name,
					sub.Version,
					"", // integrity
					"", // resolved
				))
			}
		}

		root.AppendChild(dep)
	}

	return root
}

func parsePnpmPackages(lockFile pnpmLockYaml, lockVersion float64, pnpmLock map[string]*pnpmLockPackage) {
	packageNameRegex := regexp.MustCompile(`^/?([^(]*)(?:\(.*\))*$`)
	splitChar := "/"
	if lockVersion >= 6.0 {
		splitChar = "@"
	}

	for nameVersion, packageDetails := range lockFile.Packages {
		nameVersion = packageNameRegex.ReplaceAllString(nameVersion, "$1")
		nameVersionSplit := strings.Split(strings.TrimPrefix(nameVersion, "/"), splitChar)

		// last element in split array is version
		version := nameVersionSplit[len(nameVersionSplit)-1]

		// construct name from all array items other than last item (version)
		name := strings.Join(nameVersionSplit[:len(nameVersionSplit)-1], splitChar)

		if pnpmLock[key.NpmPackageKey(name, version)] != nil {
			if pnpmLock[key.NpmPackageKey(name, version)].Version == version {
				continue
			}
		}

		packageDetails.Name = name
		packageDetails.Version = version

		pnpmLock[key.NpmPackageKey(name, version)] = packageDetails
	}
}

func parsePnpmDependencies(lockFile pnpmLockYaml, pnpmLock map[string]*pnpmLockPackage) {
	for name, info := range lockFile.Dependencies {
		version := ""
		switch info := info.(type) {
		case string:
			version = info
		case map[string]interface{}:
			v, ok := info["version"]
			if !ok {
				break
			}
			ver, ok := v.(string)
			if ok {
				version = parseVersion(ver)
			}
		default:
			log.Tracef("unsupported pnpm dependency type: %+v", info)
			continue
		}

		if pnpmLock[key.NpmPackageKey(name, version)] != nil {
			if pnpmLock[key.NpmPackageKey(name, version)].Version == version {
				continue
			}
		}

		pnpmLock[key.NpmPackageKey(name, version)] = &pnpmLockPackage{
			Name:    name,
			Version: version,
		}
	}
}

// parsePnpmLock parses a pnpm-lock.yaml file to get a list of packages
func parsePnpmLockFile(file file.LocationReadCloser) map[string]*pnpmLockPackage {
	pnpmLock := map[string]*pnpmLockPackage{}
	bytes, err := io.ReadAll(file)
	if err != nil {
		return pnpmLock
	}

	var lockFile pnpmLockYaml
	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		return pnpmLock
	}

	lockVersion, _ := strconv.ParseFloat(lockFile.Version, 64)

	// parse packages from packages section of pnpm-lock.yaml
	parsePnpmPackages(lockFile, lockVersion, pnpmLock)
	parsePnpmDependencies(lockFile, pnpmLock)

	return pnpmLock
}

func parseVersion(version string) string {
	return strings.SplitN(version, "(", 2)[0]
}
