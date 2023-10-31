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
				Name:      "ActiveDirectoryAuthenticationLibrary",
				Version:   "3.14.40721.0918",
				Locations: file.NewLocationSet(file.NewLocation("").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
				Type:      pkg.DotnetPkg,
				Language:  pkg.Dotnet,
				PURL:      "pkg:nuget/ActiveDirectoryAuthenticationLibrary@3.14.40721.0918",
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
				"FileDescription":  "äbFileVersion",
				"FileVersion":      "4.6.25512.01 built by: dlab-DDVSOWINAGE016. Commit Hash: d0d5c7b49271cadb6d97de26d8e623e98abdc8db",
				"InternalName":     "äbFileVersion",
				"LegalCopyright":   "© Microsoft Corporation.  All rights reserved.",
				"OriginalFilename": "TProductName",
				"ProductName":      "Microsoft® .NET Framework",
				"ProductVersion":   "4.6.25512.01 built by: dlab-DDVSOWINAGE016. Commit Hash: d0d5c7b49271cadb6d97de26d8e623e98abdc8db",
			},
			expectedPackage: pkg.Package{
				Name:    "bFileVersion",
				Version: "4.6.25512.01",
				Locations: file.NewLocationSet(
					file.NewLocation("").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
				Type:     pkg.DotnetPkg,
				Language: pkg.Dotnet,
				PURL:     "pkg:nuget/bFileVersion@4.6.25512.01",
				Metadata: pkg.DotnetPortableExecutableEntry{
					LegalCopyright: "© Microsoft Corporation.  All rights reserved.",
					InternalName:   "äb\x01FileVersion",
					CompanyName:    "Microsoft Corporation",
					ProductName:    "Microsoft® .NET Framework",
					ProductVersion: "4.6.25512.01 built by: dlab-DDVSOWINAGE016. Commit Hash: d0d5c7b49271cadb6d97de26d8e623e98abdc8db",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := file.LocationReadCloser{
				Location: file.NewLocation(""),
			}
			got, err := buildDotNetPackage(tc.versionResources, f)
			assert.NoErrorf(t, err, "failed to build package from version resources: %+v", tc.versionResources)
			pkgtest.AssertPackagesEqual(t, tc.expectedPackage, got)
		})
	}
}
