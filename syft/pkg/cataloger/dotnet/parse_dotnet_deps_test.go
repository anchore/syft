package dotnet

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func assertPackagesEqual(t *testing.T, actual []*pkg.Package, expected map[string]*pkg.Package) {
	assert.Len(t, actual, len(expected))
}

func TestParseDotnetDeps(t *testing.T) {
	expected := map[string]*pkg.Package{
		"AWSSDK.Core": {
			Name:         "AWSSDK.Core",
			Version:      "3.7.10.6",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "AWSSDK.Core",
				Version: "3.7.10.6",
			},
		},
		"Microsoft.Extensions.DependencyInjection": {
			Name:         "Microsoft.Extensions.DependencyInjection",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Microsoft.Extensions.DependencyInjection",
				Version: "6.0.0",
			},
		},
		"Microsoft.Extensions.DependencyInjection.Abstractions": {
			Name:         "Microsoft.Extensions.DependencyInjection.Abstractions",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Microsoft.Extensions.DependencyInjection",
				Version: "6.0.0",
			},
		},
		"Microsoft.Extensions.Logging": {
			Name:         "Microsoft.Extensions.Logging",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Microsoft.Extensions.Logging",
				Version: "6.0.0",
			},
		},
		"Microsoft.Extensions.Logging.Abstractions": {
			Name:         "Microsoft.Extensions.Logging.Abstractions",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Microsoft.Extensions.Logging",
				Version: "6.0.0",
			},
		},
		"Microsoft.Extensions.Options": {
			Name:         "Microsoft.Extensions.Options",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Microsoft.Extensions.Options",
				Version: "6.0.0",
			},
		},
		"Microsoft.Extensions.Primitives": {
			Name:         "Microsoft.Extensions.Primitives",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Microsoft.Extensions.Primitives",
				Version: "6.0.0",
			},
		},
		"Newtonsoft.Json": {
			Name:         "Newtonsoft.Json",
			Version:      "13.0.1",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Newtonsoft.Json",
				Version: "13.0.1",
			},
		},
		"Serilog": {
			Name:         "Serilog",
			Version:      "2.10.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Serilog",
				Version: "2.10.0",
			},
		},
		"Serilog.Sinks.Console": {
			Name:         "Serilog.Sinks.Console",
			Version:      "4.0.1",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "Serilog.Sinks.Console",
				Version: "4.0.1",
			},
		},
		"System.Diagnostics.DiagnosticSource": {
			Name:         "System.Diagnostics.DiagnosticSource",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "System.Diagnostics.DiagnosticSource",
				Version: "6.0.0",
			},
		},
		"System.Runtime.CompilerServices.Unsafe": {
			Name:         "System.Runtime.CompilerServices.Unsafe",
			Version:      "6.0.0",
			Language:     pkg.Dotnet,
			Type:         pkg.DotnetPkg,
			MetadataType: pkg.DotnetDepsMetadataType,
			Metadata: pkg.DotnetDepsMetadata{
				Name:    "System.Runtime.CompilerServices.Unsafe",
				Version: "6.0.0",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/TestLibrary.deps.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, _, err := parseDotnetDeps(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse deps.json: %+v", err)
	}

	assertPackagesEqual(t, actual, expected)
}
