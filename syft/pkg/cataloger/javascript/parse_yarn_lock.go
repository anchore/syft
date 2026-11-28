package javascript

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var (
	// packageAliasExp matches aliased yarn dependencies and captures the
	// underlying npm package name instead of the local alias.
	// For example: "old-async@npm:async@0.9.2" returns "async".
	packageAliasExp = regexp.MustCompile(`^"?(?:@\w[\w-_.]*\/)?\w[\w-_.]*@npm:((?:@\w[\w-_.]*\/)?\w[\w-_.]*)@`)

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
	Dependencies map[string]string
	// Descriptors are the lockfile keys for this entry, such as
	// "legacy-chalk@npm:chalk@^4.1.2" or "chalk@^5.3.0".
	Descriptors []string
}

type yarnV2PackageEntry struct {
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	Checksum     string            `yaml:"checksum"`
	Dependencies map[string]string `yaml:"dependencies"`
}

type genericYarnLockAdapter struct {
	cfg             CatalogerConfig
	licenseResolver javascriptLicenseResolver
}

func newGenericYarnLockAdapter(cfg CatalogerConfig) genericYarnLockAdapter {
	return genericYarnLockAdapter{
		cfg:             cfg,
		licenseResolver: newJavascriptLicenseResolver(cfg),
	}
}

// readPackageJSONDeps reads the package.json adjacent to the given lockfile location.
// NOTE: in yarn workspaces, only the root package.json is consulted. Packages declared
// as devDependencies only in a workspace package.json (not the root) will not be detected
// as dev-only. This is a safe degradation — those packages will be included in the SBOM
// rather than incorrectly filtered out.
func readPackageJSONDeps(resolver file.Resolver, lockfileLocation file.Location) (prod, dev map[string]string) {
	prod = make(map[string]string)
	dev = make(map[string]string)

	if resolver == nil {
		return prod, dev
	}

	pkgJSONLocation := resolver.RelativeFileByPath(lockfileLocation, "package.json")
	if pkgJSONLocation == nil {
		log.WithFields("lockfile", lockfileLocation.FullNestedPath()).Debug("could not find package.json for dev dependency detection")
		return prod, dev
	}

	reader, err := resolver.FileContentsByLocation(*pkgJSONLocation)
	if err != nil {
		log.WithFields("location", pkgJSONLocation.FullNestedPath(), "error", err).Debug("could not read package.json for dev dependency detection")
		return prod, dev
	}
	defer internal.CloseAndLogError(reader, pkgJSONLocation.FullNestedPath())

	var pkgJSON packageJSON
	if err := json.NewDecoder(reader).Decode(&pkgJSON); err != nil {
		log.WithFields("location", pkgJSONLocation.FullNestedPath(), "error", err).Debug("could not parse package.json for dev dependency detection")
		return prod, dev
	}

	if pkgJSON.Dependencies != nil {
		prod = pkgJSON.Dependencies
	}
	if pkgJSON.DevDependencies != nil {
		dev = pkgJSON.DevDependencies
	}

	return prod, dev
}

// findReachableVersions returns name@version identities reachable from roots.
// A root or dependency is matched by its lockfile descriptor first, so an
// npm: alias such as legacy-chalk@npm:chalk@^4.1.2 selects that entry rather
// than every package named chalk. Yarn Berry keys often insert an npm: protocol
// that package.json does not, so both forms are tried.
func findReachableVersions(roots map[string]string, pkgs []yarnPackage) map[string]bool {
	byDesc := make(map[string]int, len(pkgs))
	byName := make(map[string][]int, len(pkgs))
	for i := range pkgs {
		byName[pkgs[i].Name] = append(byName[pkgs[i].Name], i)
		for _, desc := range pkgs[i].Descriptors {
			byDesc[desc] = i
		}
	}

	visited := make(map[int]bool)
	reached := make(map[string]bool)
	queue := make([]int, 0, len(roots))
	enqueue := func(name, spec string) {
		for _, i := range resolveYarnDep(name, spec, byDesc, byName) {
			if !visited[i] {
				queue = append(queue, i)
			}
		}
	}
	for name, spec := range roots {
		enqueue(name, spec)
	}

	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		if visited[i] {
			continue
		}
		visited[i] = true
		p := pkgs[i]
		if p.Name != "" {
			reached[p.Name+"@"+p.Version] = true
		}
		for depName, depSpec := range p.Dependencies {
			enqueue(depName, depSpec)
		}
	}

	return reached
}

func resolveYarnDep(name, spec string, byDesc map[string]int, byName map[string][]int) []int {
	if i, ok := lookupYarnDescriptor(name, spec, byDesc); ok {
		return []int{i}
	}
	if real := npmAliasPackage(spec); real != "" {
		if idxs, ok := byName[real]; ok {
			return idxs
		}
	}
	return byName[name]
}

func lookupYarnDescriptor(name, spec string, byDesc map[string]int) (int, bool) {
	if i, ok := byDesc[name+"@"+spec]; ok {
		return i, true
	}
	if spec != "" && !strings.HasPrefix(spec, "npm:") {
		if i, ok := byDesc[name+"@npm:"+spec]; ok {
			return i, true
		}
	}
	return 0, false
}

// npmAliasPackage returns the package named by an npm: alias specifier.
// "npm:chalk@^4.1.2" is chalk. "npm:^4.1.2" is only a protocol prefix, not an alias.
func npmAliasPackage(spec string) string {
	rest, ok := strings.CutPrefix(spec, "npm:")
	if !ok || rest == "" {
		return ""
	}
	name := rest
	if strings.HasPrefix(rest, "@") {
		slash := strings.Index(rest, "/")
		if slash < 0 {
			return ""
		}
		if at := strings.LastIndex(rest, "@"); at > slash {
			name = rest[:at]
		}
	} else if at := strings.Index(rest, "@"); at >= 0 {
		name = rest[:at]
	}
	if name == "" || isYarnVersionRange(name) {
		return ""
	}
	return name
}

func isYarnVersionRange(s string) bool {
	switch s[0] {
	case '^', '~', '>', '<', '=', '*', 'v', 'x', 'X':
		return true
	}
	return s[0] >= '0' && s[0] <= '9'
}

func yarnLockDescriptors(header string) []string {
	header = strings.TrimSpace(header)
	header = strings.TrimSuffix(header, ":")
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "\"")
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func findDevOnlyPkgs(yarnPkgs []yarnPackage, prodDeps, devDeps map[string]string) map[string]bool {
	prodTransitive := findReachableVersions(prodDeps, yarnPkgs)
	devTransitive := findReachableVersions(devDeps, yarnPkgs)

	devOnly := make(map[string]bool)
	for id := range devTransitive {
		if !prodTransitive[id] {
			devOnly[id] = true
		}
	}

	return devOnly
}

func parseYarnV1LockFile(reader io.ReadCloser) ([]yarnPackage, error) {
	// TODO: refactor to use bufio.Scanner for streaming line-by-line parsing instead of reading the entire file
	content, err := io.ReadAll(reader) //nolint:gocritic // stateful multi-line parser; candidate for streaming refactor
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
			pkg.Descriptors = yarnLockDescriptors(name)
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			applyYarnV1Field(&pkg, strings.Trim(line, " "))
			continue
		}
		if strings.HasPrefix(line, "    ") {
			line = strings.Trim(line, " ")
			array := strings.Split(line, " ")
			if len(array) < 2 {
				// a dependency without a version constraint is malformed; skip it rather than guess
				continue
			}
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

// applyYarnV1Field sets the package field described by a single (already trimmed) yarn v1 field line.
func applyYarnV1Field(pkg *yarnPackage, line string) {
	array := strings.Split(line, " ")
	// a field line may be missing its value in a malformed lockfile
	var value string
	if len(array) > 1 {
		value = strings.Trim(array[1], "\"")
	}
	switch array[0] {
	case "version":
		pkg.Version = value
	case "resolved":
		name, version, resolved := findResolvedPackageAndVersion(line)
		if name != "" && version != "" && resolved != "" {
			pkg.Name = name
			pkg.Version = version
			pkg.Resolved = resolved
		} else {
			pkg.Resolved = value
		}
	case "integrity":
		pkg.Integrity = value
	}
}

func parseYarnLockYaml(reader io.ReadCloser) ([]yarnPackage, error) {
	var lockfile = map[string]yarnV2PackageEntry{}
	if err := yaml.NewDecoder(reader, yaml.AllowDuplicateMapKey()).Decode(&lockfile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yarn v2 lockfile: %w", err)
	}

	var seenPkgs = strset.New()

	pkgs := []yarnPackage{}
	for key, value := range lockfile {
		packageName := findPackageName(key)
		if packageName == "" {
			log.WithFields("key", key).Error("unable to parse yarn v2 package key")
			continue
		}

		var pkg = yarnPackage{
			Name:         packageName,
			Version:      value.Version,
			Resolved:     value.Resolution,
			Integrity:    value.Checksum,
			Dependencies: value.Dependencies,
			Descriptors:  yarnLockDescriptors(key),
		}
		var nameVersion = pkg.Name + "@" + pkg.Version

		if !seenPkgs.Has(nameVersion) {
			seenPkgs.Add(nameVersion)
			pkgs = append(pkgs, pkg)
		}
	}

	return pkgs, nil
}

func (a genericYarnLockAdapter) parseYarnLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// in the case we find yarn.lock files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the project
	if pathContainsNodeModulesDirectory(reader.LocalPath()) {
		return nil, nil, nil
	}

	// TODO: refactor to detect version from the first line via bufio.Scanner, then dispatch to a streaming parser
	data, err := io.ReadAll(reader) //nolint:gocritic // two-pass parse: version detection then format-specific parsing
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

	// get dependencies from sibling package.json for dev dependency detection
	prodDeps, devDeps := readPackageJSONDeps(resolver, reader.Location)

	devOnlyPkgs := findDevOnlyPkgs(yarnPkgs, prodDeps, devDeps)

	packages := make([]pkg.Package, 0, len(yarnPkgs))
	for _, p := range yarnPkgs {
		if devOnlyPkgs[p.Name+"@"+p.Version] && !a.cfg.IncludeDevDependencies {
			continue
		}
		packages = append(packages, newYarnLockPackage(ctx, a.licenseResolver, resolver, reader.Location, p.Name, p.Version, p.Resolved, p.Integrity, p.Dependencies))
	}

	pkg.Sort(packages)

	return packages, dependency.Resolve(yarnLockDependencySpecifier, packages), unknown.IfEmptyf(packages, "unable to determine packages")
}

func findPackageName(line string) string {
	if matches := packageAliasExp.FindStringSubmatch(line); len(matches) >= 2 {
		return matches[1]
	}
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
