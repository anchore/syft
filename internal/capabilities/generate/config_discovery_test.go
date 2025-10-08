package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestDiscoverConfigs(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	configs, err := DiscoverConfigs(repoRoot)
	require.NoError(t, err)

	// verify we discovered multiple config structs
	require.NotEmpty(t, configs, "should discover at least one config struct")

	// check for known config structs that have app-config annotations
	expectedConfigs := []string{
		"golang.CatalogerConfig",
		"golang.MainModuleVersionConfig",
		"java.ArchiveCatalogerConfig",
		"python.CatalogerConfig",
		"dotnet.CatalogerConfig",
		"kernel.LinuxKernelCatalogerConfig",
		"javascript.CatalogerConfig",
		"nix.Config",
	}

	for _, expected := range expectedConfigs {
		config, ok := configs[expected]
		require.True(t, ok, "should discover config: %s", expected)
		require.NotEmpty(t, config.Fields, "config %s should have fields", expected)
		require.Equal(t, expected, config.PackageName+"."+config.StructName)
	}

	// verify golang.CatalogerConfig fields
	golangConfig := configs["golang.CatalogerConfig"]
	require.Equal(t, "golang", golangConfig.PackageName)
	require.Equal(t, "CatalogerConfig", golangConfig.StructName)
	require.NotEmpty(t, golangConfig.Fields)

	// check for specific field
	var foundSearchLocalModCache bool
	for _, field := range golangConfig.Fields {
		if field.Name == "SearchLocalModCacheLicenses" {
			foundSearchLocalModCache = true
			require.Equal(t, "bool", field.Type)
			require.Equal(t, "golang.search-local-mod-cache-licenses", field.AppKey)
			require.NotEmpty(t, field.Description)
			require.Contains(t, field.Description, "searching for go package licenses")
		}
	}
	require.True(t, foundSearchLocalModCache, "should find SearchLocalModCacheLicenses field")

	// verify nested config struct
	golangMainModuleConfig := configs["golang.MainModuleVersionConfig"]
	require.Equal(t, "golang", golangMainModuleConfig.PackageName)
	require.Equal(t, "MainModuleVersionConfig", golangMainModuleConfig.StructName)
	require.NotEmpty(t, golangMainModuleConfig.Fields)

	// check for specific nested field
	var foundFromLDFlags bool
	for _, field := range golangMainModuleConfig.Fields {
		if field.Name == "FromLDFlags" {
			foundFromLDFlags = true
			require.Equal(t, "bool", field.Type)
			require.Equal(t, "golang.main-module-version.from-ld-flags", field.AppKey)
			require.NotEmpty(t, field.Description)
		}
	}
	require.True(t, foundFromLDFlags, "should find FromLDFlags field in MainModuleVersionConfig")

	// print summary for manual inspection
	t.Logf("Discovered %d config structs:", len(configs))
	for key, config := range configs {
		t.Logf("  %s: %d fields", key, len(config.Fields))
		for _, field := range config.Fields {
			t.Logf("    - %s (%s): %s", field.Name, field.Type, field.AppKey)
			if diff := cmp.Diff("", field.Description); diff == "" {
				t.Logf("      WARNING: field %s has no description", field.Name)
			}
		}
	}
}

func TestExtractPackageNameFromPath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "golang package",
			filePath: "syft/pkg/cataloger/golang/config.go",
			want:     "golang",
		},
		{
			name:     "java package",
			filePath: "syft/pkg/cataloger/java/config.go",
			want:     "java",
		},
		{
			name:     "python cataloger",
			filePath: "syft/pkg/cataloger/python/cataloger.go",
			want:     "python",
		},
		{
			name:     "kernel cataloger",
			filePath: "syft/pkg/cataloger/kernel/cataloger.go",
			want:     "kernel",
		},
		{
			name:     "binary classifier",
			filePath: "syft/pkg/cataloger/binary/classifier_cataloger.go",
			want:     "binary",
		},
		{
			name:     "not a cataloger path",
			filePath: "syft/pkg/other/file.go",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackageNameFromPath(tt.filePath)
			require.Equal(t, tt.want, got)
		})
	}
}
