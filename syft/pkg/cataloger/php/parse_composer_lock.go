package php

import (
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

type composerLock struct {
	Packages   []pkg.PhpComposerJSONMetadata `json:"packages"`
	PackageDev []pkg.PhpComposerJSONMetadata `json:"packages-dev"`
}

// parseComposerLock is a parser function for Composer.lock contents, returning "Default" php packages discovered.
func parseComposerLock(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs := make([]pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var lock composerLock
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse composer.lock file: %w", err)
		}
		for _, m := range lock.Packages {
			pkgs = append(
				pkgs,
				newComposerLockPackage(
					m,
					reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
				),
			)
		}
	}

	return pkgs, nil, nil
}
