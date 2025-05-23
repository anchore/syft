package dotnet

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func TestTrimLibPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty path",
			input:    "",
			expected: "",
		},
		{
			name:     "simple .NET 6.0 path",
			input:    "lib/net6.0/Humanizer.dll",
			expected: "Humanizer.dll",
		},
		{
			name:     "locale-specific resource path",
			input:    "lib/net6.0/af/Humanizer.resources.dll",
			expected: "af/Humanizer.resources.dll",
		},
		{
			name:     "netstandard path",
			input:    "lib/netstandard2.0/Serilog.Sinks.Console.dll",
			expected: "Serilog.Sinks.Console.dll",
		},
		{
			name:     "runtime-specific path",
			input:    "runtimes/linux-arm/lib/netcoreapp2.2/System.Collections.Concurrent.dll",
			expected: "System.Collections.Concurrent.dll",
		},
		{
			name:     "runtime-specific path with locale",
			input:    "runtimes/win/lib/net6.0/fr-ME/re/Microsoft.Data.SqlClient.resources.dll",
			expected: "fr-ME/re/Microsoft.Data.SqlClient.resources.dll",
		},
		{
			name:     "subdirectories",
			input:    "lib/net7.0/Microsoft/Extensions/Logging.dll",
			expected: "Microsoft/Extensions/Logging.dll",
		},
		{
			name:     "doesn't match the pattern",
			input:    "content/styles/main.css",
			expected: "content/styles/main.css",
		},
		{
			name:     "different framework format",
			input:    "lib/net472/Newtonsoft.Json.dll",
			expected: "Newtonsoft.Json.dll",
		},
		{
			name:     "frameworkless lib",
			input:    "lib/Newtonsoft.Json.dll",
			expected: "lib/Newtonsoft.Json.dll", // should not match our pattern
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := trimLibPrefix(tc.input)
			if result != tc.expected {
				t.Errorf("trimLibPrefix(%q) = %q; want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestGetLogicalDepsJSON_MergeTargets(t *testing.T) {
	deps := depsJSON{
		Location: file.NewLocation("/path/to/deps.json"),
		RuntimeTarget: runtimeTarget{
			Name: ".NETCoreApp,Version=v6.0",
		},
		// note: for this test we have two targets with the same name, which will be merged when creating a logical deps
		Targets: map[string]map[string]depsTarget{
			".NETCoreApp,Version=v6.0": {
				"Microsoft.CodeAnalysis.CSharp/4.0.0": {
					Dependencies: map[string]string{
						"Microsoft.CodeAnalysis.Common": "4.0.0",
					},
					Runtime: map[string]map[string]string{
						"lib/netcoreapp3.1/Microsoft.CodeAnalysis.CSharp.dll": {
							"assemblyVersion": "4.0.0.0",
							"fileVersion":     "4.0.21.51404",
						},
					},
					Resources: map[string]map[string]string{
						"lib/netcoreapp3.1/cs/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "cs",
						},
						"lib/netcoreapp3.1/de/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "de",
						},
						"lib/netcoreapp3.1/es/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "es",
						},
						"lib/netcoreapp3.1/fr/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "fr",
						},
						"lib/netcoreapp3.1/it/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "it",
						},
						"lib/netcoreapp3.1/ja/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "ja",
						},
						"lib/netcoreapp3.1/ko/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "ko",
						},
						"lib/netcoreapp3.1/pl/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "pl",
						},
						"lib/netcoreapp3.1/pt-BR/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "pt-BR",
						},
						"lib/netcoreapp3.1/ru/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "ru",
						},
						"lib/netcoreapp3.1/tr/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "tr",
						},
						"lib/netcoreapp3.1/zh-Hans/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "zh-Hans",
						},
						"lib/netcoreapp3.1/zh-Hant/Microsoft.CodeAnalysis.CSharp.resources.dll": {
							"locale": "zh-Hant",
						},
					},
				},
			},
			"net6.0": {
				"Microsoft.CodeAnalysis.CSharp/4.0.0": {
					Dependencies: map[string]string{
						"Microsoft.CodeAnalysis.Common": "4.0.0",
					},
					Compile: map[string]map[string]string{
						"lib/netcoreapp3.1/Microsoft.CodeAnalysis.CSharp.dll": {},
					},
				},
				"Microsoft.CodeAnalysis.Common/4.0.0": {
					Dependencies: map[string]string{
						"Microsoft.CodeAnalysis.CSharp": "4.0.0",
					},
				},
			},
		},
		Libraries: map[string]depsLibrary{
			"Microsoft.CodeAnalysis.CSharp/4.0.0": {
				Type:     "package",
				Path:     "microsoft.codeanalysis.csharp/4.0.0",
				Sha512:   "sha512-example-hash",
				HashPath: "microsoft.codeanalysis.csharp.4.0.0.nupkg.sha512",
			},
		},
	}

	result := getLogicalDepsJSON(deps, &libmanJSON{})

	assert.Equal(t, "/path/to/deps.json", result.Location.RealPath)
	assert.Equal(t, ".NETCoreApp,Version=v6.0", result.RuntimeTarget.Name)

	libPackage, exists := result.PackagesByNameVersion["Microsoft.CodeAnalysis.CSharp/4.0.0"]
	require.True(t, exists, "Expected to find the merged package")

	assert.NotNil(t, libPackage.Library)
	assert.Equal(t, "package", libPackage.Library.Type)
	assert.Equal(t, "microsoft.codeanalysis.csharp/4.0.0", libPackage.Library.Path)
	assert.Equal(t, "sha512-example-hash", libPackage.Library.Sha512)
	assert.Equal(t, "microsoft.codeanalysis.csharp.4.0.0.nupkg.sha512", libPackage.Library.HashPath)

	require.Equal(t, 2, len(libPackage.Targets), "Expected 2 targets to be merged")

	expectedRuntimePaths := map[string]string{
		"Microsoft.CodeAnalysis.CSharp.dll": "lib/netcoreapp3.1/Microsoft.CodeAnalysis.CSharp.dll",
	}
	if diff := cmp.Diff(expectedRuntimePaths, libPackage.RuntimePathsByRelativeDLLPath); diff != "" {
		t.Errorf("RuntimePathsByRelativeDLLPath mismatch (-expected +actual):\n%s", diff)
	}

	expectedResourcePaths := map[string]string{
		"cs/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/cs/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"de/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/de/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"es/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/es/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"fr/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/fr/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"it/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/it/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"ja/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/ja/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"ko/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/ko/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"pl/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/pl/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"pt-BR/Microsoft.CodeAnalysis.CSharp.resources.dll":   "lib/netcoreapp3.1/pt-BR/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"ru/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/ru/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"tr/Microsoft.CodeAnalysis.CSharp.resources.dll":      "lib/netcoreapp3.1/tr/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"zh-Hans/Microsoft.CodeAnalysis.CSharp.resources.dll": "lib/netcoreapp3.1/zh-Hans/Microsoft.CodeAnalysis.CSharp.resources.dll",
		"zh-Hant/Microsoft.CodeAnalysis.CSharp.resources.dll": "lib/netcoreapp3.1/zh-Hant/Microsoft.CodeAnalysis.CSharp.resources.dll",
	}
	if diff := cmp.Diff(expectedResourcePaths, libPackage.ResourcePathsByRelativeDLLPath); diff != "" {
		t.Errorf("ResourcePathsByRelativeDLLPath mismatch (-expected +actual):\n%s", diff)
	}

	expectedCompilePaths := map[string]string{
		"Microsoft.CodeAnalysis.CSharp.dll": "lib/netcoreapp3.1/Microsoft.CodeAnalysis.CSharp.dll",
	}
	if diff := cmp.Diff(expectedCompilePaths, libPackage.CompilePathsByRelativeDLLPath); diff != "" {
		t.Errorf("CompilePathsByRelativeDLLPath mismatch (-expected +actual):\n%s", diff)
	}

	assert.Equal(t, 0, libPackage.NativePaths.Size(), "Expected no native paths")

	assert.True(t, result.PackageNameVersions.Has("Microsoft.CodeAnalysis.CSharp/4.0.0"))
}
