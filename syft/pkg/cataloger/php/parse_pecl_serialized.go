package php

import (
	"context"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/elliotchance/phpserialize"
)

// parsePeclSerialized is a parser function for PECL metadata contents, returning "Default" php packages discovered.
func parsePeclSerialized(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs := make([]pkg.Package, 0)
	data, err := io.ReadAll(reader)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	metadata, err := phpserialize.UnmarshalAssociativeArray(
		data,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse pecl metadata file: %w", err)
	}

	name := metadata["name"].(string)
	version := metadata["version"].(map[interface{}]interface{})["release"].(string)
	license := metadata["license"].(map[interface{}]interface{})["_content"].(string)

	pkgs = append(
		pkgs,
		newPeclPackage(
			pkg.PhpPeclEntry{
				Name:    name,
				Version: version,
				License: []string{
					license,
				},
			},
			reader.Location,
		),
	)

	return pkgs, nil, nil
}
