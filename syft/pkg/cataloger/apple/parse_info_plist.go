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

// infoPlist captures the raw CFBundle keys read from an Info.plist. It is kept separate from the public
// pkg.AppleAppBundleEntry so the parser can read fields without committing to expressing all of them.
type infoPlist struct {
	CFBundleIdentifier         string   `plist:"CFBundleIdentifier"`
	CFBundleName               string   `plist:"CFBundleName"`
	CFBundleDisplayName        string   `plist:"CFBundleDisplayName"`
	CFBundleExecutable         string   `plist:"CFBundleExecutable"`
	CFBundleShortVersionString string   `plist:"CFBundleShortVersionString"`
	CFBundleVersion            string   `plist:"CFBundleVersion"`
	CFBundlePackageType        string   `plist:"CFBundlePackageType"`
	CFBundleSupportedPlatforms []string `plist:"CFBundleSupportedPlatforms"`
	LSMinimumSystemVersion     string   `plist:"LSMinimumSystemVersion"`
	MinimumOSVersion           string   `plist:"MinimumOSVersion"`
	NSHumanReadableCopyright   string   `plist:"NSHumanReadableCopyright"`
	DTPlatformName             string   `plist:"DTPlatformName"`
	DTSDKName                  string   `plist:"DTSDKName"`
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
		newAppBundlePackage(name, version, info.toEntry(), reader.Location),
	}

	return pkgs, nil, nil
}

// toEntry maps the parsed plist into the public metadata type.
func (i infoPlist) toEntry() pkg.AppleAppBundleEntry {
	return pkg.AppleAppBundleEntry{
		BundleIdentifier:     i.CFBundleIdentifier,
		Name:                 i.CFBundleName,
		DisplayName:          i.CFBundleDisplayName,
		Executable:           i.CFBundleExecutable,
		ShortVersion:         i.CFBundleShortVersionString,
		Version:              i.CFBundleVersion,
		PackageType:          i.CFBundlePackageType,
		SupportedPlatforms:   i.CFBundleSupportedPlatforms,
		MinimumSystemVersion: i.LSMinimumSystemVersion,
		MinimumOSVersion:     i.MinimumOSVersion,
		Copyright:            i.NSHumanReadableCopyright,
		PlatformName:         i.DTPlatformName,
		SDKName:              i.DTSDKName,
	}
}
