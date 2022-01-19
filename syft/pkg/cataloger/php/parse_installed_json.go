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
type installedJSONComposerV2 struct {
	Packages []pkg.PhpComposerJSONMetadata `json:"packages"`
}

func (w *installedJSONComposerV2) UnmarshalJSON(data []byte) error {
	type compv2 struct {
		Packages []pkg.PhpComposerJSONMetadata `json:"packages"`
	}
	compv2er := new(compv2)
	err := json.Unmarshal(data, &compv2er)
	if err != nil {
		// If we had an err	or, we may be dealing with a composer v.1 installed.json
		// which should be all arrays
		var packages []pkg.PhpComposerJSONMetadata
		err := json.Unmarshal(data, &packages)
		if err != nil {
			return err
		}
		w.Packages = packages
		return nil
	}
	w.Packages = compv2er.Packages
	return nil
}

// integrity check
var _ common.ParserFn = parseComposerLock

// parseComposerLock is a parser function for Composer.lock contents, returning "Default" php packages discovered.
func parseInstalledJSON(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	packages := make([]*pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock installedJSONComposerV2
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse composer.lock file: %w", err)
		}
		for _, pkgMeta := range lock.Packages {
			version := pkgMeta.Version
			name := pkgMeta.Name
			packages = append(packages, &pkg.Package{
				Name:         name,
				Version:      version,
				Language:     pkg.PHP,
				Type:         pkg.PhpComposerPkg,
				MetadataType: pkg.PhpComposerJSONMetadataType,
				Metadata:     pkgMeta,
			})
		}
	}

	return packages, nil, nil
}
