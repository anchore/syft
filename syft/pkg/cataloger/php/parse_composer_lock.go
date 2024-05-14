package php

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseComposerLock

type parsedLockData struct {
	License []string `json:"license"`
	pkg.PhpComposerLockEntry
}

type composerLock struct {
	Packages   []parsedLockData `json:"packages"`
	PackageDev []parsedLockData `json:"packages-dev"` // TODO: these are not currently included as packages in the SBOM... should they be?
}

// parseComposerLock is a parser function for Composer.lock contents, returning "Default" php packages discovered.
func parseComposerLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs := make([]pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock composerLock
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse composer.lock file: %w", err)
		}
		for _, pd := range lock.Packages {
			pkgs = append(
				pkgs,
				newComposerLockPackage(
					pd,
					reader.Location,
				),
			)
		}
	}

	return pkgs, nil, nil
}
