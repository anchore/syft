package dotnet

import (
	"context"
	"encoding/xml"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
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
			assert.Equal(t, test.expected, result)
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
					Type:           "concluded",
					URLs:           []string{syftLicenseURL},
					Locations:      file.NewLocationSet(file.NewLocation(syftLicenseURL)),
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
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetLicensesFromRemotePackage(t *testing.T) {
	fixture := "newtonsoft.json 13.0.1"

	expected := []pkg.License{
		{
			Value:          "MIT",
			SPDXExpression: "MIT",
			Type:           "declared",
			URLs:           []string{"https://licenses.nuget.org/MIT"},
			Locations:      file.LocationSet{},
		},
	}

	licenseParser := newNugetLicenseResolver(CatalogerConfig{})

	t.Run(fixture, func(t *testing.T) {
		result, _ := licenseParser.getLicensesFromRemotePackage(context.Background(), defaultProvider, "newtonsoft.json", "13.0.1")
		assert.Equal(t, expected, result)
	})
}
