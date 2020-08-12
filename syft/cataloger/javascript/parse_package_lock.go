package javascript

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parsePackageLock

// PackageLock represents a JavaScript package.lock json file
type PackageLock struct {
	Requires        bool `json:"requires"`
	LockfileVersion int  `json:"lockfileVersion"`
	Dependencies    map[string]Dependency
}

// Dependency represents a single package dependency listed in the package.lock json file
type Dependency struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Requires  map[string]string
}

// parsePackageLock parses a package.lock and returns the discovered JavaScript packages.
func parsePackageLock(_ string, reader io.Reader) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock PackageLock
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
		for name, pkgMeta := range lock.Dependencies {
			packages = append(packages, pkg.Package{
				Name:     name,
				Version:  pkgMeta.Version,
				Language: pkg.JavaScript,
				Type:     pkg.NpmPkg,
			})
		}
	}

	return packages, nil
}
