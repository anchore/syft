package php

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/pkg"
)

type ComposerLock struct {
	Packages   []Dependency `json:"packages"`
	PackageDev []Dependency `json:"packages-dev"`
}

type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseComposerLock is a parser function for Composer.lock contents, returning "Default" php packages discovered.
func parseComposerLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	packages := make([]*pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock ComposerLock
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse composer.lock file: %w", err)
		}
		for _, pkgMeta := range lock.Packages {
			version := pkgMeta.Version
			name := pkgMeta.Name
			packages = append(packages, &pkg.Package{
				Name:     name,
				Version:  version,
				Language: pkg.PHP,
				Type:     pkg.PhpComposerPkg,
			})
		}
	}

	return packages, nil, nil
}
