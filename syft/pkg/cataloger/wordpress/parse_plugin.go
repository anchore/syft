package wordpress

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const contentBufferSize = 4096

var patterns = map[string]*regexp.Regexp{
	// match example:	"Plugin Name: WP Migration"	--->	WP Migration
	"name": regexp.MustCompile(`(?i)plugin name:\s*(?P<name>.+)`),

	// match example:	"Version: 5.3"				--->	5.3
	"version": regexp.MustCompile(`(?i)version:\s*(?P<version>[\d.]+)`),

	// match example:	"License: GPLv3"			--->	GPLv3
	"license": regexp.MustCompile(`(?i)license:\s*(?P<license>\w+)`),

	// match example:	"Author: MonsterInsights"	--->	MonsterInsights
	"author": regexp.MustCompile(`(?i)author:\s*(?P<author>.+)`),

	// match example:	"Author URI: https://servmask.com/"	--->	https://servmask.com/
	"author_uri": regexp.MustCompile(`(?i)author uri:\s*(?P<author_uri>.+)`),
}

type pluginData struct {
	Licenses                 []string `mapstructure:"licenses" json:"licenses,omitempty"`
	pkg.WordpressPluginEntry `mapstructure:",squash" json:",inline"`
}

func parseWordpressPluginFiles(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var fields = make(map[string]interface{})
	buffer := make([]byte, contentBufferSize)

	_, err := reader.Read(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %s file: %w", reader.Location.Path(), err)
	}

	fileContent := string(buffer)
	for field, pattern := range patterns {
		matchMap := internal.MatchNamedCaptureGroups(pattern, fileContent)
		if value := matchMap[field]; value != "" {
			fields[field] = value
		}
	}

	name, nameOk := fields["name"]
	version, versionOk := fields["version"]

	// get a plugin name from a plugin's directory name
	pluginInstallDirectory := filepath.Base(filepath.Dir(reader.RealPath))

	if nameOk && name != "" && versionOk && version != "" {
		var metadata pluginData

		metadata.PluginInstallDirectory = pluginInstallDirectory

		author, authorOk := fields["author"]
		if authorOk && author != "" {
			metadata.Author = author.(string)
		}

		authorURI, authorURIOk := fields["author_uri"]
		if authorURIOk && authorURI != "" {
			metadata.AuthorURI = authorURI.(string)
		}

		license, licenseOk := fields["license"]
		if licenseOk && license != "" {
			licenses := make([]string, 0)
			licenses = append(licenses, license.(string))
			metadata.Licenses = licenses
		}

		pkgs = append(
			pkgs,
			newWordpressPluginPackage(
				name.(string),
				version.(string),
				metadata,
				reader.Location,
			),
		)
	}

	return pkgs, nil, nil
}
