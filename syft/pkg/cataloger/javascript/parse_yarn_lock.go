package javascript

import (
	"bufio"
	"context"
	"fmt"
	"regexp"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

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

	// resolvedExp matches the resolved of the dependency in yarn.lock
	// For example:
	// 		resolved "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d"
	// 			would return "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d"
	resolvedExp = regexp.MustCompile(`^\s+resolved\s+"(.+?)"`)

	// integrityExp matches the integrity of the dependency in yarn.lock
	// For example:
	//		integrity sha512-tHq6qdbT9U1IRSGf14CL0pUlULksvY9OZ+5eEgl1N7t+OA3tGvNpxJCzuKQlsNgCVwbAs670L1vcVQi8j9HjnA==
	// 			would return "sha512-tHq6qdbT9U1IRSGf14CL0pUlULksvY9OZ+5eEgl1N7t+OA3tGvNpxJCzuKQlsNgCVwbAs670L1vcVQi8j9HjnA==""
	integrityExp = regexp.MustCompile(`^\s+integrity\s+([^\s]+)`)
)

type genericYarnLockAdapter struct {
	cfg CatalogerConfig
}

func newGenericYarnLockAdapter(cfg CatalogerConfig) genericYarnLockAdapter {
	return genericYarnLockAdapter{
		cfg: cfg,
	}
}

func (a genericYarnLockAdapter) parseYarnLock(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// in the case we find yarn.lock files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the project
	if pathContainsNodeModulesDirectory(reader.Path()) {
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	var currentPackage, currentVersion, currentResolved, currentIntegrity string

	scanner := bufio.NewScanner(reader)
	parsedPackages := strset.New()

	for scanner.Scan() {
		line := scanner.Text()

		if packageName := findPackageName(line); packageName != "" {
			// When we find a new package, check if we have unsaved identifiers
			if currentPackage != "" && currentVersion != "" && !parsedPackages.Has(currentPackage+"@"+currentVersion) {
				pkgs = append(pkgs, newYarnLockPackage(a.cfg, resolver, reader.Location, currentPackage, currentVersion, currentResolved, currentIntegrity))
				parsedPackages.Add(currentPackage + "@" + currentVersion)
			}

			currentPackage = packageName
		} else if version := findPackageVersion(line); version != "" {
			currentVersion = version
		} else if packageName, version, resolved := findResolvedPackageAndVersion(line); packageName != "" && version != "" && resolved != "" {
			currentResolved = resolved
			currentPackage = packageName
			currentVersion = version
		} else if integrity := findIntegrity(line); integrity != "" && !parsedPackages.Has(currentPackage+"@"+currentVersion) {
			pkgs = append(pkgs, newYarnLockPackage(a.cfg, resolver, reader.Location, currentPackage, currentVersion, currentResolved, integrity))
			parsedPackages.Add(currentPackage + "@" + currentVersion)

			// Cleanup to indicate no unsaved identifiers
			currentPackage = ""
			currentVersion = ""
			currentResolved = ""
			currentIntegrity = ""
		}
	}

	// check if we have valid unsaved data after end-of-file has reached
	if currentPackage != "" && currentVersion != "" && !parsedPackages.Has(currentPackage+"@"+currentVersion) {
		pkgs = append(pkgs, newYarnLockPackage(a.cfg, resolver, reader.Location, currentPackage, currentVersion, currentResolved, currentIntegrity))
		parsedPackages.Add(currentPackage + "@" + currentVersion)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yarn.lock file: %w", err)
	}

	pkg.Sort(pkgs)

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func findPackageName(line string) string {
	if matches := packageNameExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

func findPackageVersion(line string) string {
	if matches := versionExp.FindStringSubmatch(line); len(matches) >= 2 {
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

func findIntegrity(line string) string {
	if matches := integrityExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}

	return ""
}
