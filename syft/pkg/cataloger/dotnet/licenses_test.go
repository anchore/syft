package dotnet

import (
	"context"
	"encoding/xml"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/require"
)

func TestRemoveBOM(t *testing.T) {
	content := []byte("as expected")
	tests := []struct {
		name     string
		in       []byte
		expected []byte
	}{
		{
			name: "empty",
		},
		{
			name:     "UTF-16 (BE)",
			in:       append([]byte{254, 255}, content...),
			expected: content,
		},
		{
			name:     "UTF-16 (LE)",
			in:       append([]byte{255, 254}, content...),
			expected: content,
		},
		{
			name:     "UTF-8",
			in:       append([]byte{239, 187, 191}, content...),
			expected: content,
		},
		{
			name:     "UTF-32 (BE)",
			in:       append([]byte{0, 0, 254, 255}, content...),
			expected: content,
		},
		{
			name:     "UTF-32 (LE)",
			in:       append([]byte{255, 254, 0, 0}, content...),
			expected: content,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := removeBOM(test.in)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestExtractLicensesFromNuSpec(t *testing.T) {
	syftLicenseURL := "https://raw.githubusercontent.com/anchore/syft/refs/tags/v1.14.1/LICENSE"
	tests := []struct {
		name     string
		spec     nugetSpecification
		expected []pkg.License
	}{
		{
			name: "expression",
			spec: nugetSpecification{
				XMLName: xml.Name{},
				Xmlns:   "",
				Meta: nuspecMetaData{
					License: nuspecLicense{
						Text: "MIT",
						Type: "expression",
					},
				},
				Files: nuspecFiles{},
			},
			expected: []pkg.License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           "declared",
					Locations:      file.LocationSet{},
				},
			},
		},
		{
			name: "legacy",
			spec: nugetSpecification{
				XMLName: xml.Name{},
				Xmlns:   "",
				Meta: nuspecMetaData{
					LicenseURL: syftLicenseURL,
				},
				Files: nuspecFiles{},
			},
			expected: []pkg.License{
				{
					Value:          "Apache-2.0",
					SPDXExpression: "Apache-2.0",
					Type:           "declared",
					URLs:           []string{syftLicenseURL},
					Locations:      file.LocationSet{},
				},
			},
		},
		{
			name: "fallback (without real package archive)",
			spec: nugetSpecification{
				XMLName: xml.Name{},
				Xmlns:   "",
				Meta:    nuspecMetaData{},
				Files: nuspecFiles{
					File: []nuspecFile{
						{
							Source: "LICENSE.md",
						},
					},
				},
			},
			expected: []pkg.License{},
		},
	}

	licenseParser := newNugetLicenseResolver(CatalogerConfig{})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := licenseParser.extractLicensesFromNuSpec(context.Background(), test.spec, nil)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestGetLicensesFromRemotePackage(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected []pkg.License
	}{
		{
			name:    "newtonsoft.json",
			version: "13.0.1",
			expected: []pkg.License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           "declared",
					URLs:           []string{"https://licenses.nuget.org/MIT"},
					Locations:      file.LocationSet{},
				},
			},
		},
		{
			name:    "bouncycastle.cryptography",
			version: "2.6.2",
			expected: []pkg.License{
				{
					Value:          "MIT",
					SPDXExpression: "MIT",
					Type:           "declared",
					URLs:           []string{"https://licenses.nuget.org/MIT"},
					Locations:      file.LocationSet{},
				},
			},
		},
		{
			name:    "log4net",
			version: "3.2.0",
			expected: []pkg.License{
				{
					Value:          "Apache-2.0",
					SPDXExpression: "Apache-2.0",
					Type:           "declared",
					URLs:           []string{"https://licenses.nuget.org/Apache-2.0"},
					Locations:      file.LocationSet{},
				},
			},
		},
	}

	licenseParser := newNugetLicenseResolver(CatalogerConfig{})

	for _, test := range tests {
		t.Run(test.name+" "+test.version, func(t *testing.T) {
			result, success := licenseParser.getLicensesFromRemotePackage(context.Background(), defaultNuGetProvider, test.name, test.version)
			require.True(t, success)
			require.Equal(t, test.expected, result)
		})
	}
}
