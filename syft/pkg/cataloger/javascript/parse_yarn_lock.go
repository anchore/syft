package javascript

import (
	"bufio"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseYarnLock

var (
	// packageNameExp matches the name of the dependency in yarn.lock
	// including scope/namespace prefix if found.
	// For example: "aws-sdk@2.706.0" returns "aws-sdk"
	//              "@babel/code-frame@^7.0.0" returns "@babel/code-frame"
	packageNameExp = regexp.MustCompile(`^"?((?:@\w[\w-_.]*\/)?\w[\w-_.]*)@`)

	// versionExp matches the "version" line of a yarn.lock entry and captures the version value.
	// For example: version "4.10.1" (...and the value "4.10.1" is captured)
	versionExp = regexp.MustCompile(`^\W+version(?:\W+"|:\W+)([\w-_.]+)"?`)

	// packageURLExp matches the name and version of the dependency in yarn.lock
	// from the resolved URL, including scope/namespace prefix if any.
	// For example:
	//		`resolved "https://registry.yarnpkg.com/async/-/async-3.2.3.tgz#ac53dafd3f4720ee9e8a160628f18ea91df196c9"`
	//			would return "async" and "3.2.3"
	//
	//		`resolved "https://registry.yarnpkg.com/@4lolo/resize-observer-polyfill/-/resize-observer-polyfill-1.5.2.tgz#58868fc7224506236b5550d0c68357f0a874b84b"`
	//			would return "@4lolo/resize-observer-polyfill" and "1.5.2"
	packageURLExp = regexp.MustCompile(`^\s+resolved\s+"https://registry\.(?:yarnpkg\.com|npmjs\.org)/(.+?)/-/(?:.+?)-(\d+\..+?)\.tgz`)
)

const (
	noPackage = ""
	noVersion = ""
)

func parseYarnLock(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	// in the case we find yarn.lock files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the project
	if pathContainsNodeModulesDirectory(path) {
		return nil, nil, nil
	}

	var packages []*pkg.Package
	scanner := bufio.NewScanner(reader)
	parsedPackages := internal.NewStringSet()
	currentPackage := noPackage
	currentVersion := noVersion

	for scanner.Scan() {
		line := scanner.Text()

		if packageName := findPackageName(line); packageName != noPackage {
			// When we find a new package, check if we have unsaved identifiers
			if currentPackage != noPackage && currentVersion != noVersion && !parsedPackages.Contains(currentPackage+"@"+currentVersion) {
				packages = append(packages, newYarnLockPackage(currentPackage, currentVersion))
				parsedPackages.Add(currentPackage + "@" + currentVersion)
			}

			currentPackage = packageName
		} else if version := findPackageVersion(line); version != noVersion {
			currentVersion = version
		} else if packageName, version := findPackageAndVersion(line); packageName != noPackage && version != noVersion && !parsedPackages.Contains(packageName+"@"+version) {
			packages = append(packages, newYarnLockPackage(packageName, version))
			parsedPackages.Add(packageName + "@" + version)

			// Cleanup to indicate no unsaved identifiers
			currentPackage = noPackage
			currentVersion = noVersion
		}
	}

	// check if we have valid unsaved data after end-of-file has reached
	if currentPackage != noPackage && currentVersion != noVersion && !parsedPackages.Contains(currentPackage+"@"+currentVersion) {
		packages = append(packages, newYarnLockPackage(currentPackage, currentVersion))
		parsedPackages.Add(currentPackage + "@" + currentVersion)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yarn.lock file: %w", err)
	}

	return packages, nil, nil
}

func findPackageName(line string) string {
	if matches := packageNameExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}

	return noPackage
}

func findPackageVersion(line string) string {
	if matches := versionExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}

	return noVersion
}

func findPackageAndVersion(line string) (string, string) {
	if matches := packageURLExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1], matches[2]
	}

	return noPackage, noVersion
}

func newYarnLockPackage(name, version string) *pkg.Package {
	return &pkg.Package{
		Name:     name,
		Version:  version,
		Language: pkg.JavaScript,
		Type:     pkg.NpmPkg,
	}
}
