package javascript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

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
	Dev       bool   `json:"dev"`
}

type lockPackage struct {
	Name         string             `json:"name"` // only present in the root package entry (named "")
	Version      string             `json:"version"`
	Resolved     string             `json:"resolved"`
	Integrity    string             `json:"integrity"`
	License      packageLockLicense `json:"license"`
	Dev          bool               `json:"dev"`
	Dependencies map[string]string  `json:"dependencies"`
}

// packageLockLicense
type packageLockLicense []string

type genericPackageLockAdapter struct {
	cfg CatalogerConfig
}

func newGenericPackageLockAdapter(cfg CatalogerConfig) genericPackageLockAdapter {
	return genericPackageLockAdapter{
		cfg: cfg,
	}
}

// parsePackageLock parses a package-lock.json and returns the discovered JavaScript packages.
func (a genericPackageLockAdapter) parsePackageLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// in the case we find package-lock.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(reader.Path()) {
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	dec := json.NewDecoder(reader)

	var lock packageLock
	for {
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
	}

	if lock.LockfileVersion == 1 {
		for name, pkgMeta := range lock.Dependencies {
			// skip packages that are only present as a dev dependency
			if !a.cfg.IncludeDevDependencies && pkgMeta.Dev {
				continue
			}

			pkgs = append(pkgs, newPackageLockV1Package(ctx, a.cfg, resolver, reader.Location, name, pkgMeta))
		}
	}

	if lock.LockfileVersion == 2 || lock.LockfileVersion == 3 {
		for name, pkgMeta := range lock.Packages {
			if name == "" {
				if pkgMeta.Name == "" {
					continue
				}
				name = pkgMeta.Name
			}

			// skip packages that are only present as a dev dependency
			if !a.cfg.IncludeDevDependencies && pkgMeta.Dev {
				continue
			}

			// handles alias names
			if pkgMeta.Name != "" {
				name = pkgMeta.Name
			}

			newPkg := newPackageLockV2Package(ctx, a.cfg, resolver, reader.Location, getNameFromPath(name), pkgMeta)
			pkgs = append(pkgs, newPkg)
		}
	}

	pkg.Sort(pkgs)

	return pkgs, dependency.Resolve(packageLockDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func (licenses *packageLockLicense) UnmarshalJSON(data []byte) (err error) {
	// The license field could be either a string or an array.

	// 1. An array
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*licenses = arr
		return nil
	}

	// 2. A string
	var str string
	if err = json.Unmarshal(data, &str); err == nil {
		*licenses = make([]string, 1)
		(*licenses)[0] = str
		return nil
	}

	// debug the content we did not expect
	if len(data) > 0 {
		log.WithFields("license", string(data)).Debug("Unable to parse the following `license` value in package-lock.json")
	}

	// 3. Unexpected
	// In case we are unable to parse the license field,
	// i.e if we have not covered the full specification,
	// we do not want to throw an error, instead assign nil.
	return nil
}

func getNameFromPath(path string) string {
	parts := strings.Split(path, "node_modules/")
	return parts[len(parts)-1]
}
