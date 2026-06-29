package apple

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
	// 5MB cap matches the convention in syft/linux; Info.plist files are far smaller
	data, err := io.ReadAll(io.LimitReader(reader, 5*1024*1024))
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
	if name == "" {
		// last-resort name so identifiable bundles aren't dropped (e.g. com.apple.Safari)
		name = info.CFBundleIdentifier
	}

	version := info.CFBundleShortVersionString
	if version == "" {
		version = info.CFBundleVersion
	}

	if name == "" || version == "" {
		return nil, nil, nil
	}

	pkgs := []pkg.Package{
		newAppBundlePackage(name, version, info.CFBundleIdentifier, reader.Location),
	}

	return pkgs, nil, nil
}
