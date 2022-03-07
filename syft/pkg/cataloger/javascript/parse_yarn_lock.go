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

	for scanner.Scan() {
		line := scanner.Text()

		if currentPackage == noPackage {
			// Scan until we find the next package

			packageName := findPackageName(line)
			if packageName == noPackage {
				continue
			}

			if parsedPackages.Contains(packageName) {
				// We don't parse repeated package declarations.
				continue
			}

			currentPackage = packageName
			parsedPackages.Add(currentPackage)

			continue
		}

		// We've found the package entry, now we just need the version

		if version := findPackageVersion(line); version != noVersion {
			packages = append(packages, newYarnLockPackage(currentPackage, version))
			currentPackage = noPackage

			continue
		}
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

func newYarnLockPackage(name, version string) *pkg.Package {
	return &pkg.Package{
		Name:     name,
		Version:  version,
		Language: pkg.JavaScript,
		Type:     pkg.NpmPkg,
	}
}
