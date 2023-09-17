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

func newPnpmLockPackage(resolver file.Resolver, location file.Location, p *pnpmLockPackage) pkg.Package {
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

func parsePnpmLock(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pnpmMap, pnpmLock := parsePnpmLockFile(reader)
	pkgs, _ := finalizePnpmLockWithoutPackageJSON(resolver, &pnpmLock, pnpmMap, reader.Location)
	return pkgs, nil, nil
}

func finalizePnpmLockWithoutPackageJSON(resolver file.Resolver, _ *pnpmLockYaml, pnpmMap map[string]*pnpmLockPackage, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	seenPkgMap := make(map[string]bool)
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	name := rootNameFromPath(indexLocation)
	if name == "" {
		return nil, nil
	}
	root := newPnpmLockPackage(resolver, indexLocation, &pnpmLockPackage{Name: name, Version: "0.0.0"})
	pkgs = append(pkgs, root)

	for _, lockPkg := range pnpmMap {
		if seenPkgMap[key.NpmPackageKey(lockPkg.Name, lockPkg.Version)] {
			continue
		}

		pkg := newPnpmLockPackage(resolver, indexLocation, lockPkg)
		pkgs = append(pkgs, pkg)
		seenPkgMap[key.NpmPackageKey(pkg.Name, pkg.Version)] = true
	}

	pkg.Sort(pkgs)
	pkg.SortRelationships(relationships)
	return pkgs, relationships
}

func finalizePnpmLockWithPackageJSON(resolver file.Resolver, pkgjson *packageJSON, pnpmLock *pnpmLockYaml, pnpmMap map[string]*pnpmLockPackage, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	seenPkgMap := make(map[string]bool)
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	root := newPnpmLockPackage(resolver, indexLocation, &pnpmLockPackage{Name: pkgjson.Name, Version: pkgjson.Version})
	pkgs = append(pkgs, root)

	// create root relationships
	for name, info := range pnpmLock.Dependencies {
		version := parsePnpmDependencyInfo(info)
		if version == "" {
			continue
		}

		p := pnpmMap[key.NpmPackageKey(name, version)]
		pkg := newPnpmLockPackage(resolver, indexLocation, p)
		rel := artifact.Relationship{
			From: pkg,
			To:   root,
			Type: artifact.DependencyOfRelationship,
		}
		relationships = append(relationships, rel)
	}

	// create packages
	for _, lockPkg := range pnpmMap {
		if seenPkgMap[key.NpmPackageKey(lockPkg.Name, lockPkg.Version)] {
			continue
		}

		pkg := newPnpmLockPackage(resolver, indexLocation, lockPkg)
		pkgs = append(pkgs, pkg)
		seenPkgMap[key.NpmPackageKey(pkg.Name, pkg.Version)] = true
	}

	// create pkg relationships
	for _, lockPkg := range pnpmMap {
		p := pnpmMap[key.NpmPackageKey(lockPkg.Name, lockPkg.Version)]
		pkg := newPnpmLockPackage(
			resolver,
			indexLocation,
			p,
		)

		for name, version := range lockPkg.Dependencies {
			dep := pnpmMap[key.NpmPackageKey(name, version)]
			depPkg := newPnpmLockPackage(
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

func parsePnpmDependencyInfo(info interface{}) (version string) {
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
	}
	log.Tracef("unsupported pnpm dependency type: %+v", info)
	return
}

func parsePnpmDependencies(lockFile pnpmLockYaml, pnpmLock map[string]*pnpmLockPackage) {
	for name, info := range lockFile.Dependencies {
		version := parsePnpmDependencyInfo(info)
		if version == "" {
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
func parsePnpmLockFile(file file.LocationReadCloser) (map[string]*pnpmLockPackage, pnpmLockYaml) {
	pnpmLock := map[string]*pnpmLockPackage{}
	bytes, err := io.ReadAll(file)
	if err != nil {
		return pnpmLock, pnpmLockYaml{}
	}

	var lockFile pnpmLockYaml
	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		return pnpmLock, pnpmLockYaml{}
	}

	lockVersion, _ := strconv.ParseFloat(lockFile.Version, 64)

	// parse packages from packages section of pnpm-lock.yaml
	parsePnpmPackages(lockFile, lockVersion, pnpmLock)
	parsePnpmDependencies(lockFile, pnpmLock)

	return pnpmLock, lockFile
}

func parseVersion(version string) string {
	return strings.SplitN(version, "(", 2)[0]
}
