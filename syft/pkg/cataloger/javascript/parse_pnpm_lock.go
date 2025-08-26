package javascript

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parsePnpmLock

type pnpmLockYaml struct {
	Version      string                 `json:"lockfileVersion" yaml:"lockfileVersion"`
	Dependencies map[string]interface{} `json:"dependencies" yaml:"dependencies"`
	Packages     map[string]interface{} `json:"packages" yaml:"packages"`
}

func parsePnpmLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load pnpm-lock.yaml file: %w", err)
	}

	var pkgs []pkg.Package
	var lockFile pnpmLockYaml

	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pnpm-lock.yaml file: %w", err)
	}

	lockVersion, _ := strconv.ParseFloat(lockFile.Version, 64)

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

		if hasPkg(pkgs, name, version) {
			continue
		}

		pkgs = append(pkgs, newPnpmPackage(ctx, resolver, reader.Location, name, version))
	}

	packageNameRegex := regexp.MustCompile(`^/?([^(]*)(?:\(.*\))*$`)
	splitChar := "/"
	if lockVersion >= 6.0 {
		splitChar = "@"
	}

	// parse packages from packages section of pnpm-lock.yaml
	for nameVersion := range lockFile.Packages {
		nameVersion = packageNameRegex.ReplaceAllString(nameVersion, "$1")
		nameVersionSplit := strings.Split(strings.TrimPrefix(nameVersion, "/"), splitChar)

		// last element in split array is version
		version := nameVersionSplit[len(nameVersionSplit)-1]

		// construct name from all array items other than last item (version)
		name := strings.Join(nameVersionSplit[:len(nameVersionSplit)-1], splitChar)

		if hasPkg(pkgs, name, version) {
			continue
		}

		pkgs = append(pkgs, newPnpmPackage(ctx, resolver, reader.Location, name, version))
	}

	pkg.Sort(pkgs)

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func hasPkg(pkgs []pkg.Package, name, version string) bool {
	for _, p := range pkgs {
		if p.Name == name && p.Version == version {
			return true
		}
	}
	return false
}

func parseVersion(version string) string {
	return strings.SplitN(version, "(", 2)[0]
}
