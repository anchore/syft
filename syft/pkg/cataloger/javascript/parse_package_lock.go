package javascript

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

// integrity check
var _ generic.Parser = parsePackageLock

// packageLock represents a JavaScript package.lock json file
type packageLock struct {
	Requires        bool `json:"requires"`
	LockfileVersion int  `json:"lockfileVersion"`
	Dependencies    map[string]lockDependency
	Packages        map[string]lockPackage
}

// lockDependency represents a single package dependency listed in the package.lock json file
type lockDependency struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

type lockPackage struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	License   string `json:""`
}

// parsePackageLock parses a package-lock.json and returns the discovered JavaScript packages.
func parsePackageLock(resolver source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// in the case we find package-lock.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(reader.AccessPath()) {
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	dec := json.NewDecoder(reader)

	for {
		var lock packageLock
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
		licenseMap := make(map[string]string)
		for _, pkgMeta := range lock.Packages {
			var sb strings.Builder
			sb.WriteString(pkgMeta.Resolved)
			sb.WriteString(pkgMeta.Integrity)
			licenseMap[sb.String()] = pkgMeta.License
		}

		for name, pkgMeta := range lock.Dependencies {
			pkgs = append(pkgs, newPackageLockPackage(resolver, reader.Location, name, pkgMeta, licenseMap))
		}
	}

	pkg.Sort(pkgs)

	return pkgs, nil, nil
}
