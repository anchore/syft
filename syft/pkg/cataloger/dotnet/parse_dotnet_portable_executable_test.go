package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseDotnetPortableExecutable(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/System.Buffers.dll",
			expected: []pkg.Package{
				{
					Name:    "System.Buffers",
					Version: "7.0.923.36201",
					Type:    pkg.DotnetPkg,
					PURL:    "pkg:nuget/System.Buffers@7.0.923.36201",
					Metadata: pkg.DotnetPortableExecutableEntry{
						AssemblyVersion: "7.0.0.0",
						LegalCopyright:  "© Microsoft Corporation. All rights reserved.",
						Comments:        "System.Buffers",
						InternalName:    "System.Buffers.dll",
						CompanyName:     "Microsoft Corporation",
						ProductName:     "Microsoft® .NET",
						ProductVersion:  "7.0.9+8e9a17b2216f51a5788f8b1c467a4cf3b769e7d7",
					},
				},
			},
		},
		{
			fixture: "test-fixtures/Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll",
			expected: []pkg.Package{
				{
					Name:    "ActiveDirectoryAuthenticationLibrary",
					Version: "3.14.40721.0918",
					Type:    pkg.DotnetPkg,
					PURL:    "pkg:nuget/ActiveDirectoryAuthenticationLibrary@3.14.40721.0918",
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
		},
		{
			fixture: "test-fixtures/sni.dll",
			expected: []pkg.Package{
				{
					Name:    "bFileVersion",
					Version: "4.6.25512.01",
					Type:    pkg.DotnetPkg,
					PURL:    "pkg:nuget/bFileVersion@4.6.25512.01",
					Metadata: pkg.DotnetPortableExecutableEntry{
						LegalCopyright: "© Microsoft Corporation.  All rights reserved.",
						CompanyName:    "Microsoft Corporation",
						ProductName:    "Microsoft® .NET Framework",
						ProductVersion: "4.6.25512.01 built by: dlab-DDVSOWINAGE016. Commit Hash: d0d5c7b49271cadb6d97de26d8e623e98abdc8db",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			fixtureLocationSet := file.NewLocationSet(file.NewLocation(tc.fixture))
			tc.expected[0].Locations = fixtureLocationSet
			var expectedRelationships []artifact.Relationship
			pkgtest.TestFileParser(t, tc.fixture, parseDotnetPortableExecutable, tc.expected, expectedRelationships)
		})
	}
}
