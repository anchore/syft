package npm

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
)

type PackageLock struct {
	Requires        bool `json:"requires"`
	LockfileVersion int  `json:"lockfileVersion"`
	Dependencies    Dependencies
}

type Dependency struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Requires  map[string]string
}

type Dependencies map[string]Dependency

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
