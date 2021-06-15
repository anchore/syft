package javascript

import (
	"bufio"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseYarnLock

var (
	composedNameExp = regexp.MustCompile(`^"(@[^@]+)`)
	simpleNameExp   = regexp.MustCompile(`^(\w[\w-_.]*)@`)
	versionExp      = regexp.MustCompile(`^\W+version\W+"([\w-_.]+)"`)
)

const (
	noPackage = ""
	noVersion = ""
)

func parseYarnLock(_ string, reader io.Reader) ([]pkg.Package, error) {
	var packages []pkg.Package

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
		return nil, fmt.Errorf("failed to parse yarn.lock file: %w", err)
	}

	return packages, nil
}

func findPackageName(line string) string {
	if matches := composedNameExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}

	if matches := simpleNameExp.FindStringSubmatch(line); len(matches) >= 2 {
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

func newYarnLockPackage(name, version string) pkg.Package {
	return pkg.Package{
		Name:     name,
		Version:  version,
		Language: pkg.JavaScript,
		Type:     pkg.NpmPkg,
	}
}
