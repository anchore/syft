package javascript

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var (
	// packageNameExp matches the name of the dependency in yarn.lock
	// including scope/namespace prefix if found.
	// For example: "aws-sdk@2.706.0" returns "aws-sdk"
	//              "@babel/code-frame@^7.0.0" returns "@babel/code-frame"
	packageNameExp = regexp.MustCompile(`^"?((?:@\w[\w-_.]*\/)?\w[\w-_.]*)@`)

	// packageURLExp matches the name and version of the dependency in yarn.lock
	// from the resolved URL, including scope/namespace prefix if any.
	// For example:
	//		`resolved "https://registry.yarnpkg.com/async/-/async-3.2.3.tgz#ac53dafd3f4720ee9e8a160628f18ea91df196c9"`
	//			would return "async" and "3.2.3"
	//
	//		`resolved "https://registry.yarnpkg.com/@4lolo/resize-observer-polyfill/-/resize-observer-polyfill-1.5.2.tgz#58868fc7224506236b5550d0c68357f0a874b84b"`
	//			would return "@4lolo/resize-observer-polyfill" and "1.5.2"
	packageURLExp = regexp.MustCompile(`^resolved\s+"https://registry\.(?:yarnpkg\.com|npmjs\.org)/(.+?)/-/(?:.+?)-(\d+\..+?)\.tgz`)

	// resolvedExp matches the resolved of the dependency in yarn.lock
	// For example:
	// 		resolved "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d"
	// 			would return "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d"
	resolvedExp = regexp.MustCompile(`^resolved\s+"(.+?)"`)
)

type yarnPackage struct {
	Name         string
	Version      string
	Resolved     string
	Integrity    string
	Dependencies map[string]string // We don't currently support dependencies for yarn v1 lock files
}

type yarnV2PackageEntry struct {
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	Checksum     string            `yaml:"checksum"`
	Dependencies map[string]string `yaml:"dependencies"`
}

type genericYarnLockAdapter struct {
	cfg CatalogerConfig
}

func newGenericYarnLockAdapter(cfg CatalogerConfig) genericYarnLockAdapter {
	return genericYarnLockAdapter{
		cfg: cfg,
	}
}

func parseYarnV1LockFile(reader io.ReadCloser) ([]yarnPackage, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read yarn.lock file: %w", err)
	}

	re := regexp.MustCompile(`\r?\n`)
	lines := re.Split(string(content), -1)
	var pkgs []yarnPackage
	var pkg = yarnPackage{}
	var seenPkgs = strset.New()
	dependencies := make(map[string]string)

	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Blank lines indicate the end of a package entry, so we add the package
		// to the list and reset the dependencies
		if len(line) == 0 && len(pkg.Name) > 0 && !seenPkgs.Has(pkg.Name+"@"+pkg.Version) {
			pkg.Dependencies = dependencies
			pkgs = append(pkgs, pkg)
			seenPkgs.Add(pkg.Name + "@" + pkg.Version)
			dependencies = make(map[string]string)
			pkg = yarnPackage{}
			continue
		}
		// The first line of a package entry is the name of the package with no
		// leading spaces
		if !strings.HasPrefix(line, " ") {
			name := line
			pkg.Name = findPackageName(name)
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			line = strings.Trim(line, " ")
			array := strings.Split(line, " ")
			switch array[0] {
			case "version":
				pkg.Version = strings.Trim(array[1], "\"")
			case "resolved":
				name, version, resolved := findResolvedPackageAndVersion(line)
				if name != "" && version != "" && resolved != "" {
					pkg.Name = name
					pkg.Version = version
					pkg.Resolved = resolved
				} else {
					pkg.Resolved = strings.Trim(array[1], "\"")
				}
			case "integrity":
				pkg.Integrity = strings.Trim(array[1], "\"")
			}
			continue
		}
		if strings.HasPrefix(line, "    ") {
			line = strings.Trim(line, " ")
			array := strings.Split(line, " ")
			dependencyName := strings.Trim(array[0], "\"")
			dependencyVersion := strings.Trim(array[1], "\"")
			dependencies[dependencyName] = dependencyVersion
		}
	}
	// If the last package in the list is not the same as the current package, add the current package
	// to the list. In case there was no trailing new line before we hit EOF.
	if len(pkg.Name) > 0 && !seenPkgs.Has(pkg.Name+"@"+pkg.Version) {
		pkg.Dependencies = dependencies
		pkgs = append(pkgs, pkg)
		seenPkgs.Add(pkg.Name + "@" + pkg.Version)
	}

	return pkgs, nil
}

func parseYarnLockYaml(reader io.ReadCloser) ([]yarnPackage, error) {
	var lockfile = map[string]yarnV2PackageEntry{}
	if err := yaml.NewDecoder(reader, yaml.AllowDuplicateMapKey()).Decode(&lockfile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yarn v2 lockfile: %w", err)
	}

	packages := make(map[string]yarnPackage)
	for key, value := range lockfile {
		packageName := findPackageName(key)
		if packageName == "" {
			log.WithFields("key", key).Error("unable to parse yarn v2 package key")
			continue
		}

		packages[packageName] = yarnPackage{Name: packageName, Version: value.Version, Resolved: value.Resolution, Integrity: value.Checksum, Dependencies: value.Dependencies}
	}

	return slices.Collect(maps.Values(packages)), nil
}

func (a genericYarnLockAdapter) parseYarnLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// in the case we find yarn.lock files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the project
	if pathContainsNodeModulesDirectory(reader.Path()) {
		return nil, nil, nil
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load yarn.lock file: %w", err)
	}
	// Reset the reader to the beginning of the file
	reader.ReadCloser = io.NopCloser(bytes.NewBuffer(data))

	var yarnPkgs []yarnPackage
	// v1 Yarn lockfiles are not YAML, so we need to parse them as a special case. They typically
	// include a comment line that indicates the version. I.e. "# yarn lockfile v1"
	if strings.Contains(string(data), "# yarn lockfile v1") {
		yarnPkgs, err = parseYarnV1LockFile(reader)
	} else {
		yarnPkgs, err = parseYarnLockYaml(reader)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse yarn.lock file: %w", err)
	}

	packages := make([]pkg.Package, len(yarnPkgs))
	for i, p := range yarnPkgs {
		packages[i] = newYarnLockPackage(ctx, a.cfg, resolver, reader.Location, p.Name, p.Version, p.Resolved, p.Integrity, p.Dependencies)
	}

	pkg.Sort(packages)

	return packages, dependency.Resolve(yarnLockDependencySpecifier, packages), unknown.IfEmptyf(packages, "unable to determine packages")
}

func findPackageName(line string) string {
	if matches := packageNameExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

func findResolvedPackageAndVersion(line string) (string, string, string) {
	var resolved string
	if matches := resolvedExp.FindStringSubmatch(line); len(matches) >= 2 {
		resolved = matches[1]
	}
	if matches := packageURLExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1], matches[2], resolved
	}

	return "", "", ""
}
