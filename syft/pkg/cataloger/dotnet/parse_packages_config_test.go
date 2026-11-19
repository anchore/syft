package dotnet

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseDotnetPackagesConfig(t *testing.T) {
	fixture := "testdata/packages-config/packages.config"
	var expected []pkg.Package
	for _, entry := range []struct{ name, version string }{
		{"Newtonsoft.Json", "13.0.3"}, {"NUnit", "3.14.0"}, {"Example.Library", "1.0.0-beta.1"},
	} {
		expected = append(expected, pkg.Package{
			Name: entry.name, Version: entry.version, Type: pkg.DotnetPkg, Language: pkg.Dotnet,
			PURL:      "pkg:nuget/" + entry.name + "@" + entry.version,
			Locations: file.NewLocationSet(file.NewLocation(fixture)),
		})
	}
	pkgtest.NewCatalogTester().FromFile(t, fixture).Expects(expected, nil).TestParser(t, parseDotnetPackagesConfig)
}

func TestDotnetPackagesConfigCataloger(t *testing.T) {
	pkgtest.NewCatalogTester().FromDirectory(t, "testdata/packages-config").
		ExpectsResolverContentQueries([]string{"packages.config", "nested/packages.config"}).
		TestCataloger(t, NewDotnetPackagesConfigCataloger())
}

func TestParseDotnetPackagesConfigInvalidAndEmpty(t *testing.T) {
	for _, tt := range []struct {
		name, contents string
		wantErr        bool
	}{
		{"empty packages", "<packages/>", false},
		{"missing required fields", `<packages><package id="MissingVersion"/><package version="1"/><package id=" " version="1"/></packages>`, false},
		{"malformed XML", `<packages><package id="A" version="1"></packages>`, true},
		{"wrong root", `<configuration><package id="A" version="1"/></configuration>`, true},
		{"empty file", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader := file.NewLocationReadCloser(file.NewLocation("packages.config"), io.NopCloser(strings.NewReader(tt.contents)))
			packages, relationships, err := parseDotnetPackagesConfig(context.Background(), nil, nil, reader)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Empty(t, packages)
			assert.Empty(t, relationships)
		})
	}
}

func TestParseDotnetPackagesConfigBOM(t *testing.T) {
	reader := file.NewLocationReadCloser(file.NewLocation("packages.config"), io.NopCloser(strings.NewReader("\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"utf-8\"?><packages><package id=\"A\" version=\"1.2.3\" /></packages>")))
	packages, relationships, err := parseDotnetPackagesConfig(context.Background(), nil, nil, reader)
	require.NoError(t, err)
	require.Len(t, packages, 1)
	assert.Equal(t, "pkg:nuget/A@1.2.3", packages[0].PURL)
	assert.Empty(t, relationships)
}
