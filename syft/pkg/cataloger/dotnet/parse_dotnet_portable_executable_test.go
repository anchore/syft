package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseDotnetPortableExecutable(t *testing.T) {
	fixture := "test-fixtures/System.Buffers.dll"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	expected := []pkg.Package{
		{
			Name:         "System.Buffers",
			Version:      "7.0.923.36201",
			Locations:    fixtureLocationSet,
			Type:         pkg.DotnetPkg,
			PURL:         "pkg:nuget/System.Buffers@7.0.923.36201",
			MetadataType: pkg.DotnetPortableExecutableMetadataType,
			Metadata: pkg.DotnetPortableExecutableMetadata{
				AssemblyVersion: "7.0.0.0",
				LegalCopyright:  "© Microsoft Corporation. All rights reserved.",
				Comments:        "System.Buffers",
				InternalName:    "System.Buffers.dll",
				CompanyName:     "Microsoft Corporation",
				ProductName:     "Microsoft® .NET",
				ProductVersion:  "7.0.9+8e9a17b2216f51a5788f8b1c467a4cf3b769e7d7",
			},
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseDotnetPortableExecutable, expected, expectedRelationships)
}
