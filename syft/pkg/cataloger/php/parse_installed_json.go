package php

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// Note: composer version 2 introduced a new structure for the installed.json file, so we support both
type InstalledJsonComposerV2 struct {
	Packages   []Dependency `json:"packages"`
}

type InstalledJsonComposerV1 struct {
	Packages []Dependency
}

//
//type Dependency struct {
//	Name    string `json:"name"`
//	Version string `json:"version"`
//}

func (w *InstalledJsonComposerV2) UnmarshalJSON(data []byte) error {
	if data[0] == '{' { //we're dealing with composer 2
		type compv2 struct {
			Packages []Dependency `json:"packages"`
		}
		compv2er := new(compv2)
		err := json.Unmarshal(data, &compv2er)
		if(err != nil) {
			return err
		}
		w.Packages = compv2er.Packages
		return nil
	}
	//we're falling back on composer 1, which should be all arrays
	var packages []Dependency
	err := json.Unmarshal(data, &packages)
	if err != nil {
		return err
	}
	w.Packages = packages
	return nil
}

// integrity check
var _ common.ParserFn = parseComposerLock

// parseComposerLock is a parser function for Composer.lock contents, returning "Default" php packages discovered.
func parseInstalledJson(_ string, reader io.Reader) ([]pkg.Package, []artifact.Relationship, error) {
	packages := make([]pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock InstalledJsonComposerV2
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse composer.lock file: %w", err)
		}
		for _, pkgMeta := range lock.Packages {
			version := pkgMeta.Version
			name := pkgMeta.Name
			packages = append(packages, pkg.Package{
				Name:     name,
				Version:  version,
				Language: pkg.PHP,
				Type:     pkg.PhpComposerPkg,
			})
		}
	}

	return packages, nil, nil
}
