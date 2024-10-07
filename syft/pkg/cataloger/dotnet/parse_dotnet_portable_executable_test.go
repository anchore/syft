package dotnet

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseDotnetPortableExecutable(t *testing.T) {
	tests := []struct {
		name             string
		versionResources map[string]string
		expectedPackage  pkg.Package
	}{
		{
			name: "dotnet package with extra version info",
			versionResources: map[string]string{
				"InternalName":     "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll",
				"FileVersion":      "3.14.40721.0918    xxxfffdddjjjj",
				"FileDescription":  "Active Directory Authentication Library",
				"ProductName":      "Active Directory Authentication Library",
				"Comments":         "",
				"CompanyName":      "Microsoft Corporation",
				"LegalTrademarks":  "",
				"LegalCopyright":   "Copyright (c) Microsoft Corporation. All rights reserved.",
				"OriginalFilename": "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll",
				"ProductVersion":   "c61f043686a544863efc014114c42e844f905336",
				"Assembly Version": "3.14.2.11",
			},
			expectedPackage: pkg.Package{
				Name:    "Active Directory Authentication Library",
				Version: "3.14.40721.0918",
				Metadata: pkg.DotnetPortableExecutableEntry{
					AssemblyVersion: "3.14.2.11",
					LegalCopyright:  "Copyright (c) Microsoft Corporation. All rights reserved.",
					InternalName:    "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll",
					CompanyName:     "Microsoft Corporation",
					ProductName:     "Active Directory Authentication Library",
					ProductVersion:  "c61f043686a544863efc014114c42e844f905336",
				},
			},
		},
		{
			name: "dotnet package with malformed field and extended version",
			versionResources: map[string]string{
				"CompanyName":      "Microsoft Corporation",
				"FileDescription":  "äbFile\xa0\xa1Versi on",
				"FileVersion":      "4.6.25512.01 built by: dlab-DDVSOWINAGE016. Commit Hash: d0d5c7b49271cadb6d97de26d8e623e98abdc8db",
				"InternalName":     "äbFileVersion",
				"LegalCopyright":   "© Microsoft Corporation.  All rights reserved.",
				"OriginalFilename": "TProductName",
				"ProductName":      "Microsoft® .NET Framework",
				"ProductVersion":   "4.6.25512.01 built by: dlab-DDVSOWINAGE016. Commit Hash: d0d5c7b49271cadb6d97de26d8e623e98abdc8db",
			},
			expectedPackage: pkg.Package{
				Name:    "äbFileVersi on",
				Version: "4.6.25512.01",
				PURL:    "pkg:nuget/%C3%A4bFileVersi%20on@4.6.25512.01",
				Metadata: pkg.DotnetPortableExecutableEntry{
					LegalCopyright: "© Microsoft Corporation.  All rights reserved.",
					InternalName:   "äb\x01FileVersion",
					CompanyName:    "Microsoft Corporation",
					ProductName:    "Microsoft® .NET Framework",
					ProductVersion: "4.6.25512.01 built by: dlab-DDVSOWINAGE016. Commit Hash: d0d5c7b49271cadb6d97de26d8e623e98abdc8db",
				},
			},
		},
		{
			name: "System.Data.Linq.dll",
			versionResources: map[string]string{
				"CompanyName":      "Microsoft Corporation",
				"FileDescription":  "System.Data.Linq.dll",
				"FileVersion":      "4.7.3190.0 built by: NET472REL1LAST_C",
				"InternalName":     "System.Data.Linq.dll",
				"LegalCopyright":   "© Microsoft Corporation.  All rights reserved.",
				"OriginalFilename": "System.Data.Linq.dll",
				"ProductName":      "Microsoft® .NET Framework",
				"ProductVersion":   "4.7.3190.0",
			},
			expectedPackage: pkg.Package{
				Name:    "System.Data.Linq.dll",
				Version: "4.7.3190.0",
			},
		},
		{
			name: "curl",
			versionResources: map[string]string{
				"CompanyName":      "curl, https://curl.se/",
				"FileDescription":  "The curl executable",
				"FileVersion":      "8.4.0",
				"InternalName":     "curl",
				"LegalCopyright":   "© Daniel Stenberg, <daniel@haxx.se>.",
				"OriginalFilename": "curl.exe",
				"ProductName":      "The curl executable",
				"ProductVersion":   "8.4.0",
			},
			expectedPackage: pkg.Package{
				Name:    "The curl executable",
				Version: "8.4.0",
			},
		},
		{
			name: "Prometheus",
			versionResources: map[string]string{
				"AssemblyVersion":  "8.0.0.0",
				"CompanyName":      "",
				"FileDescription":  "",
				"FileVersion":      "8.0.1",
				"InternalName":     "Prometheus.AspNetCore.dll",
				"OriginalFilename": "Prometheus.AspNetCore.dll",
				"ProductName":      "",
				"ProductVersion":   "8.0.1",
			},
			expectedPackage: pkg.Package{
				Name:    "Prometheus.AspNetCore.dll",
				Version: "8.0.1",
			},
		},
		{
			name: "Hidden Input",
			versionResources: map[string]string{
				"FileDescription":  "Reads from stdin without leaking info to the terminal and outputs back to stdout",
				"FileVersion":      "1, 0, 0, 0",
				"InternalName":     "hiddeninput",
				"LegalCopyright":   "Jordi Boggiano - 2012",
				"OriginalFilename": "hiddeninput.exe",
				"ProductName":      "Hidden Input",
				"ProductVersion":   "1, 0, 0, 0",
			},
			expectedPackage: pkg.Package{
				Name:    "Hidden Input",
				Version: "1, 0, 0, 0",
			},
		},
		{
			name: "SQLite3",
			versionResources: map[string]string{
				"CompanyName":     "SQLite Development Team",
				"FileDescription": "SQLite is a software library that implements a self-contained, serverless, zero-configuration, transactional SQL database engine.",
				"FileVersion":     "3.23.2",
				"InternalName":    "sqlite3",
				"LegalCopyright":  "http://www.sqlite.org/copyright.html",
				"ProductName":     "SQLite",
				"ProductVersion":  "3.23.2",
			},
			expectedPackage: pkg.Package{
				Name:    "SQLite",
				Version: "3.23.2",
			},
		},
		{
			name: "Brave Browser",
			versionResources: map[string]string{
				"CompanyName":      "Brave Software, Inc.",
				"FileDescription":  "Brave Browser",
				"FileVersion":      "80.1.7.92",
				"InternalName":     "chrome_exe",
				"LegalCopyright":   "Copyright 2016 The Brave Authors. All rights reserved.",
				"OriginalFilename": "chrome.exe",
				"ProductName":      "Brave Browser",
				"ProductVersion":   "80.1.7.92",
			},
			expectedPackage: pkg.Package{
				Name:    "Brave Browser",
				Version: "80.1.7.92",
			},
		},
		{
			name: "Better product version",
			versionResources: map[string]string{
				"FileDescription": "Better version",
				"FileVersion":     "80.1.7",
				"ProductVersion":  "80.1.7.92",
			},
			expectedPackage: pkg.Package{
				Name:    "Better version",
				Version: "80.1.7.92",
			},
		},
		{
			name: "Better file version",
			versionResources: map[string]string{
				"FileDescription": "Better version",
				"FileVersion":     "80.1.7.92",
				"ProductVersion":  "80.1.7",
			},
			expectedPackage: pkg.Package{
				Name:    "Better version",
				Version: "80.1.7.92",
			},
		},
		{
			name: "Higher semantic version Product Version",
			versionResources: map[string]string{
				"FileDescription": "Higher semantic version Product Version",
				"FileVersion":     "3.0.0.0",
				"ProductVersion":  "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
			expectedPackage: pkg.Package{
				Name:    "Higher semantic version Product Version",
				Version: "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
		},
		{
			name: "Higher semantic version File Version",
			versionResources: map[string]string{
				"FileDescription": "Higher semantic version File Version",
				"FileVersion":     "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
				"ProductVersion":  "3.0.0",
			},
			expectedPackage: pkg.Package{
				Name:    "Higher semantic version File Version",
				Version: "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
		},
		{
			name: "Invalid semantic version File Version",
			versionResources: map[string]string{
				"FileDescription": "Invalid semantic version File Version",
				"FileVersion":     "A",
				"ProductVersion":  "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
			expectedPackage: pkg.Package{
				Name:    "Invalid semantic version File Version",
				Version: "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
		},
		{
			name: "Invalid semantic version File Version",
			versionResources: map[string]string{
				"FileDescription": "Invalid semantic version File Version",
				"FileVersion":     "A",
				"ProductVersion":  "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
			expectedPackage: pkg.Package{
				Name:    "Invalid semantic version File Version",
				Version: "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
		},
		{
			name: "Invalid semantic version Product Version",
			versionResources: map[string]string{
				"FileDescription": "Invalid semantic version Product Version",
				"FileVersion":     "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
				"ProductVersion":  "A",
			},
			expectedPackage: pkg.Package{
				Name:    "Invalid semantic version Product Version",
				Version: "3.0.1+b86b61bf676163639795b163d8d753b20aad6207",
			},
		},
		{
			name: "Semantically equal falls through, chooses File Version with more components",
			versionResources: map[string]string{
				"FileDescription": "Semantically equal falls through, chooses File Version with more components",
				"FileVersion":     "3.0.0.0",
				"ProductVersion":  "3.0.0",
			},
			expectedPackage: pkg.Package{
				Name:    "Semantically equal falls through, chooses File Version with more components",
				Version: "3.0.0.0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			location := file.NewLocation("")
			f := file.LocationReadCloser{
				Location: location,
			}
			got, err := buildDotNetPackage(tc.versionResources, f)
			assert.NoErrorf(t, err, "failed to build package from version resources: %+v", tc.versionResources)

			// ignore certain metadata
			if tc.expectedPackage.Metadata == nil {
				got.Metadata = nil
			}
			// set known defaults
			if tc.expectedPackage.Type == "" {
				tc.expectedPackage.Type = pkg.DotnetPkg
			}
			if tc.expectedPackage.Language == "" {
				tc.expectedPackage.Language = pkg.Dotnet
			}
			if tc.expectedPackage.PURL == "" {
				tc.expectedPackage.PURL = portableExecutablePackageURL(tc.expectedPackage.Name, tc.expectedPackage.Version)
			}
			tc.expectedPackage.Locations = file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

			pkgtest.AssertPackagesEqual(t, tc.expectedPackage, got)
		})
	}
}

func Test_corruptDotnetPE(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/something.exe").
		WithError().
		TestParser(t, parseDotnetPortableExecutable)
}

func Test_extractVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "1, 0, 0, 0",
			expected: "1, 0, 0, 0",
		},
		{
			input:    "Release 73",
			expected: "Release 73",
		},
		{
			input:    "4.7.4076.0 built by: NET472REL1LAST_B",
			expected: "4.7.4076.0",
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got := extractVersion(test.input)
			assert.Equal(t, test.expected, got)
		})
	}
}

func Test_spaceNormalize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			expected: "some spaces apart",
			input:    " some 	spaces\n\t\t \n\rapart\n",
		},
		{
			expected: "söme ¡nvalid characters",
			input:    "\rsöme \u0001¡nvalid\t characters\n",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			got := spaceNormalize(test.input)
			assert.Equal(t, test.expected, got)
		})
	}
}
