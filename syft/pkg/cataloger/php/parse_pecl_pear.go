package php

import (
	"context"
	"fmt"
	"io"

	"github.com/elliotchance/phpserialize"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type peclPearData struct {
	Name    string
	Channel string
	Version string
	License []string
}

func (p *peclPearData) ToPear() pkg.PhpPearEntry {
	return pkg.PhpPearEntry{
		Name:    p.Name,
		Channel: p.Channel,
		Version: p.Version,
		License: p.License,
	}
}

func (p *peclPearData) ToPecl() pkg.PhpPeclEntry { //nolint:staticcheck
	return pkg.PhpPeclEntry(p.ToPear()) //nolint:staticcheck
}

func parsePecl(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	m, err := parsePeclPearSerialized(reader)
	if err != nil {
		return nil, nil, err
	}
	if m == nil {
		return nil, nil, unknown.New(reader.Location, fmt.Errorf("no pecl package found"))
	}
	return []pkg.Package{newPeclPackage(ctx, *m, reader.Location)}, nil, nil
}

func parsePear(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	m, err := parsePeclPearSerialized(reader)
	if err != nil {
		return nil, nil, err
	}
	if m == nil {
		return nil, nil, unknown.New(reader.Location, fmt.Errorf("no pear package found"))
	}
	return []pkg.Package{newPearPackage(ctx, *m, reader.Location)}, nil, nil
}

// parsePeclPearSerialized is a parser function for Pear metadata contents, returning "Default" php packages discovered.
func parsePeclPearSerialized(reader file.LocationReadCloser) (*peclPearData, error) {
	data, err := io.ReadAll(reader)

	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	metadata, err := phpserialize.UnmarshalAssociativeArray(
		data,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to parse pear metadata file: %w", err)
	}

	name, ok := metadata["name"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse pear package name: %w", err)
	}

	channel, ok := metadata["channel"].(string)
	if !ok {
		// this could be the v5 format
		channel = ""
	}

	version := readStruct(metadata, "version", "release")
	license := readStruct(metadata, "license", "_content")

	return &peclPearData{
		Name:    name,
		Channel: channel,
		Version: version,
		License: []string{
			license,
		},
	}, nil
}

func readStruct(metadata any, fields ...string) string {
	if len(fields) > 0 {
		value, ok := metadata.(map[any]any)
		if !ok {
			return ""
		}
		return readStruct(value[fields[0]], fields[1:]...)
	}
	value, ok := metadata.(string)
	if !ok {
		return ""
	}
	return value
}
