package macos

import (
	"context"
	"fmt"
	"io"

	"howett.net/plist"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type infoPlist struct {
	CFBundleDisplayName        string `plist:"CFBundleDisplayName"`
	CFBundleName               string `plist:"CFBundleName"`
	CFBundleExecutable         string `plist:"CFBundleExecutable"`
	CFBundleIdentifier         string `plist:"CFBundleIdentifier"`
	CFBundleShortVersionString string `plist:"CFBundleShortVersionString"`
	CFBundleVersion            string `plist:"CFBundleVersion"`
}

func parseInfoPlist(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read file: %w", err)
	}

	var info infoPlist
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return nil, nil, fmt.Errorf("unable to parse plist: %w", err)
	}

	name := info.CFBundleDisplayName
	if name == "" {
		name = info.CFBundleName
	}
	if name == "" {
		name = info.CFBundleExecutable
	}

	version := info.CFBundleShortVersionString
	if version == "" {
		version = info.CFBundleVersion
	}

	if name == "" || version == "" {
		return nil, nil, nil
	}

	pkgs := []pkg.Package{
		newMacOSAppPackage(name, version, info.CFBundleIdentifier, reader.Location),
	}

	return pkgs, nil, nil
}
