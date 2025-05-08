package php

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseComposerLock

// Note: composer version 2 introduced a new structure for the installed.json file, so we support both
type installedJSONComposerV2 struct {
	Packages []parsedInstalledData `json:"packages"`
}

type parsedInstalledData struct {
	License []string `json:"license"`
	pkg.PhpComposerInstalledEntry
}

func (w *installedJSONComposerV2) UnmarshalJSON(data []byte) error {
	type compv2 struct {
		Packages []parsedInstalledData `json:"packages"`
	}
	compv2er := new(compv2)
	err := json.Unmarshal(data, &compv2er)
	if err != nil {
		// If we had an err	or, we may be dealing with a composer v.1 installed.json
		// which should be all arrays
		var packages []parsedInstalledData
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

// parseInstalledJSON is a parser function for Composer.lock contents, returning "Default" php packages discovered.
func parseInstalledJSON(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	dec := json.NewDecoder(reader)

	for {
		var lock installedJSONComposerV2
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse installed.json file: %w", err)
		}
		for _, pd := range lock.Packages {
			pkgs = append(
				pkgs,
				newComposerInstalledPackage(
					pd,
					reader.Location,
				),
			)
		}
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
