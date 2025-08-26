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
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func TestParseDotnetCsproj(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      []pkg.Package
		expectedError bool
	}{
		{
			name: "basic PackageReference parsing",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog" Version="2.10.0" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
				{
					Name:     "Serilog",
					Version:  "2.10.0",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Serilog@2.10.0",
				},
			},
		},
		{
			name: "skip private assets",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="StyleCop.Analyzers" Version="1.2.0" PrivateAssets="all" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" PrivateAssets="All" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
			},
		},
		{
			name: "skip conditional debug-only references",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" Condition="'$(Configuration)' == 'Debug'" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
			},
		},
		{
			name: "complex IncludeAssets and PrivateAssets handling",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="StyleCop.Analyzers" Version="1.2.0" PrivateAssets="all" />
    <PackageReference Include="Microsoft.ChakraCore" Version="1.11.24" IncludeAssets="runtime; build; native" />
    <PackageReference Include="NUnit" Version="3.13.3" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
				{
					Name:     "Microsoft.ChakraCore",
					Version:  "1.11.24",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Microsoft.ChakraCore@1.11.24",
				},
			},
		},
		{
			name: "skip build-time packages",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" />
    <PackageReference Include="StyleCop.Analyzers" Version="1.2.0" />
    <PackageReference Include="Microsoft.CodeAnalysis.Analyzers" Version="3.3.4" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
			},
		},
		{
			name: "skip packages without version",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
			},
		},
		{
			name: "multiple ItemGroup elements",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="Serilog" Version="2.10.0" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
				{
					Name:     "Serilog",
					Version:  "2.10.0",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Serilog@2.10.0",
				},
			},
		},
		{
			name: "empty project",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>`,
			expected: []pkg.Package{},
		},
		{
			name: "ProjectReference ignored",
			input: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <ProjectReference Include="../SharedLibrary/SharedLibrary.csproj" />
  </ItemGroup>
</Project>`,
			expected: []pkg.Package{
				{
					Name:     "Newtonsoft.Json",
					Version:  "13.0.3",
					Language: pkg.Dotnet,
					Type:     pkg.DotnetPkg,
					PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
				},
			},
		},
		{
			name:          "malformed XML",
			input:         `<Project><ItemGroup><PackageReference Include="Test"`,
			expected:      nil,
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := file.NewLocationReadCloser(
				file.NewLocation("/test/project.csproj"),
				io.NopCloser(strings.NewReader(test.input)),
			)

			packages, relationships, err := parseDotnetCsproj(context.Background(), nil, &generic.Environment{}, reader)

			if test.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Empty(t, relationships)
			require.Len(t, packages, len(test.expected))

			for i, expectedPkg := range test.expected {
				actualPkg := packages[i]
				assert.Equal(t, expectedPkg.Name, actualPkg.Name)
				assert.Equal(t, expectedPkg.Version, actualPkg.Version)
				assert.Equal(t, expectedPkg.Language, actualPkg.Language)
				assert.Equal(t, expectedPkg.Type, actualPkg.Type)
				assert.Equal(t, expectedPkg.PURL, actualPkg.PURL)

				// Verify metadata structure
				metadata, ok := actualPkg.Metadata.(pkg.DotnetDepsEntry)
				require.True(t, ok, "expected DotnetDepsEntry metadata")
				assert.Equal(t, expectedPkg.Name, metadata.Name)
				assert.Equal(t, expectedPkg.Version, metadata.Version)
				assert.NotEmpty(t, metadata.Path)

				// Verify locations are set
				assert.NotEmpty(t, actualPkg.Locations)
			}
		})
	}
}

func TestShouldSkipPackageReference(t *testing.T) {
	tests := []struct {
		name     string
		ref      csprojPackageReference
		expected bool
	}{
		{
			name: "regular package",
			ref: csprojPackageReference{
				Include: "Newtonsoft.Json",
				Version: "13.0.3",
			},
			expected: false,
		},
		{
			name: "private assets all",
			ref: csprojPackageReference{
				Include:       "StyleCop.Analyzers",
				Version:       "1.2.0",
				PrivateAssets: "all",
			},
			expected: true,
		},
		{
			name: "private assets All (capitalized)",
			ref: csprojPackageReference{
				Include:       "StyleCop.Analyzers",
				Version:       "1.2.0",
				PrivateAssets: "All",
			},
			expected: true,
		},
		{
			name: "debug condition",
			ref: csprojPackageReference{
				Include:   "Microsoft.NET.Test.Sdk",
				Version:   "17.8.0",
				Condition: "'$(Configuration)' == 'Debug'",
			},
			expected: true,
		},
		{
			name: "test SDK package",
			ref: csprojPackageReference{
				Include: "Microsoft.NET.Test.Sdk",
				Version: "17.8.0",
			},
			expected: true,
		},
		{
			name: "stylecop analyzer",
			ref: csprojPackageReference{
				Include: "StyleCop.Analyzers",
				Version: "1.2.0",
			},
			expected: true,
		},
		{
			name: "code analysis package",
			ref: csprojPackageReference{
				Include: "Microsoft.CodeAnalysis.Analyzers",
				Version: "3.3.4",
			},
			expected: true,
		},
		{
			name: "includeAssets runtime only",
			ref: csprojPackageReference{
				Include: "Some.Package",
				Version: "1.0.0",
				IncludeAssets: "runtime",
			},
			expected: false,
		},
		{
			name: "mixed condition with release",
			ref: csprojPackageReference{
				Include: "Some.Package",
				Version: "1.0.0",
				Condition: "'$(Configuration)' == 'Debug' OR '$(Configuration)' == 'Release'",
			},
			expected: false,
		},
		{
			name: "nunit test package",
			ref: csprojPackageReference{
				Include: "NUnit",
				Version: "3.13.3",
			},
			expected: true,
		},
		{
			name: "mstest framework",
			ref: csprojPackageReference{
				Include: "MSTest.TestFramework",
				Version: "3.1.1",
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := shouldSkipPackageReference(test.ref)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestBuildPackageFromReference(t *testing.T) {
	tests := []struct {
		name     string
		ref      csprojPackageReference
		location file.Location
		expected *pkg.Package
	}{
		{
			name: "valid package reference",
			ref: csprojPackageReference{
				Include: "Newtonsoft.Json",
				Version: "13.0.3",
			},
			location: file.NewLocation("/test/project.csproj"),
			expected: &pkg.Package{
				Name:     "Newtonsoft.Json",
				Version:  "13.0.3",
				Language: pkg.Dotnet,
				Type:     pkg.DotnetPkg,
				PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
			},
		},
		{
			name: "empty name",
			ref: csprojPackageReference{
				Include: "",
				Version: "13.0.3",
			},
			location: file.NewLocation("/test/project.csproj"),
			expected: nil,
		},
		{
			name: "empty version",
			ref: csprojPackageReference{
				Include: "Newtonsoft.Json",
				Version: "",
			},
			location: file.NewLocation("/test/project.csproj"),
			expected: nil,
		},
		{
			name: "whitespace in name and version",
			ref: csprojPackageReference{
				Include: "  Newtonsoft.Json  ",
				Version: "  13.0.3  ",
			},
			location: file.NewLocation("/test/project.csproj"),
			expected: &pkg.Package{
				Name:     "Newtonsoft.Json",
				Version:  "13.0.3",
				Language: pkg.Dotnet,
				Type:     pkg.DotnetPkg,
				PURL:     "pkg:nuget/Newtonsoft.Json@13.0.3",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := buildPackageFromReference(test.ref, test.location)

			if test.expected == nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, test.expected.Name, result.Name)
			assert.Equal(t, test.expected.Version, result.Version)
			assert.Equal(t, test.expected.Language, result.Language)
			assert.Equal(t, test.expected.Type, result.Type)
			assert.Equal(t, test.expected.PURL, result.PURL)

			// Verify metadata
			metadata, ok := result.Metadata.(pkg.DotnetDepsEntry)
			require.True(t, ok)
			assert.Equal(t, test.expected.Name, metadata.Name)
			assert.Equal(t, test.expected.Version, metadata.Version)
		})
	}
}
