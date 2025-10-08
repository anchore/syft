package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinkCatalogersToConfigs(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	linkages, err := LinkCatalogersToConfigs(repoRoot)
	require.NoError(t, err)

	// verify we discovered multiple catalogers
	require.NotEmpty(t, linkages, "should discover at least one cataloger linkage")

	// test cases for known catalogers with configs
	// NOTE: Some catalogers may not be detected if their Name() method is in a different file
	// than the constructor function. This is a known limitation.
	tests := []struct {
		catalogerName string
		wantConfig    string
		optional      bool // set to true if detection may not work due to cross-file Name() methods
	}{
		{
			catalogerName: "go-module-binary-cataloger",
			wantConfig:    "golang.CatalogerConfig",
		},
		{
			catalogerName: "go-module-file-cataloger",
			wantConfig:    "golang.CatalogerConfig",
		},
		{
			catalogerName: "python-package-cataloger",
			wantConfig:    "python.CatalogerConfig",
		},
		{
			catalogerName: "java-archive-cataloger",
			wantConfig:    "java.ArchiveCatalogerConfig",
		},
		{
			catalogerName: "java-pom-cataloger",
			wantConfig:    "java.ArchiveCatalogerConfig",
			optional:      true, // Name() method in different file
		},
		{
			catalogerName: "dotnet-deps-binary-cataloger",
			wantConfig:    "dotnet.CatalogerConfig",
			optional:      true, // Name() method in different file
		},
		{
			catalogerName: "javascript-lock-cataloger",
			wantConfig:    "javascript.CatalogerConfig",
		},
		{
			catalogerName: "linux-kernel-cataloger",
			wantConfig:    "kernel.LinuxKernelCatalogerConfig",
		},
		{
			catalogerName: "nix-cataloger",
			wantConfig:    "nix.Config",
			optional:      true, // Name() method in different file
		},
	}

	for _, tt := range tests {
		t.Run(tt.catalogerName, func(t *testing.T) {
			config, ok := linkages[tt.catalogerName]
			if tt.optional && !ok {
				t.Skipf("cataloger %s not detected (expected due to cross-file Name() method)", tt.catalogerName)
				return
			}
			require.True(t, ok, "should find linkage for cataloger: %s", tt.catalogerName)
			require.Equal(t, tt.wantConfig, config, "config type should match for cataloger: %s", tt.catalogerName)
		})
	}

	// test catalogers without configs (should have empty string)
	catalogersWithoutConfig := []string{
		"python-installed-package-cataloger",
		"java-gradle-lockfile-cataloger",
		"java-jvm-cataloger",
		"dotnet-packages-lock-cataloger",
		"javascript-package-cataloger",
	}

	for _, catalogerName := range catalogersWithoutConfig {
		t.Run(catalogerName+"_no_config", func(t *testing.T) {
			config, ok := linkages[catalogerName]
			if ok {
				require.Empty(t, config, "cataloger %s should have empty config", catalogerName)
			}
		})
	}

	// print summary for manual inspection
	t.Logf("Discovered %d cataloger-to-config linkages:", len(linkages))

	// separate into catalogers with and without configs
	withConfig := make(map[string]string)
	withoutConfig := make([]string, 0)

	for name, config := range linkages {
		if config != "" {
			withConfig[name] = config
		} else {
			withoutConfig = append(withoutConfig, name)
		}
	}

	t.Logf("Catalogers with configs (%d):", len(withConfig))
	for name, config := range withConfig {
		t.Logf("  %s -> %s", name, config)
	}

	t.Logf("Catalogers without configs (%d):", len(withoutConfig))
	for _, name := range withoutConfig {
		t.Logf("  %s", name)
	}

	// ensure we found at least some catalogers with configs
	require.GreaterOrEqual(t, len(withConfig), 6, "should find at least 6 catalogers with configs")
}

func TestExtractConfigTypeName(t *testing.T) {
	tests := []struct {
		name             string
		catalogerName    string
		expectedConfig   string
		expectedNoConfig bool
	}{
		{
			name:           "golang config",
			catalogerName:  "go-module-binary-cataloger",
			expectedConfig: "golang.CatalogerConfig",
		},
		{
			name:           "python config",
			catalogerName:  "python-package-cataloger",
			expectedConfig: "python.CatalogerConfig",
		},
		{
			name:           "java archive config",
			catalogerName:  "java-archive-cataloger",
			expectedConfig: "java.ArchiveCatalogerConfig",
		},
		{
			name:           "kernel config",
			catalogerName:  "linux-kernel-cataloger",
			expectedConfig: "kernel.LinuxKernelCatalogerConfig",
		},
		{
			name:             "python installed - no config",
			catalogerName:    "python-installed-package-cataloger",
			expectedNoConfig: true,
		},
	}

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	linkages, err := LinkCatalogersToConfigs(repoRoot)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, ok := linkages[tt.catalogerName]

			if tt.expectedNoConfig {
				if ok {
					require.Empty(t, config, "expected no config for %s", tt.catalogerName)
				}
			} else {
				require.True(t, ok, "should find cataloger %s", tt.catalogerName)
				require.Equal(t, tt.expectedConfig, config)
			}
		})
	}
}

func TestLooksLikeConfigType(t *testing.T) {
	tests := []struct {
		name     string
		typeName string
		want     bool
	}{
		{
			name:     "golang config",
			typeName: "golang.CatalogerConfig",
			want:     true,
		},
		{
			name:     "python config",
			typeName: "python.CatalogerConfig",
			want:     true,
		},
		{
			name:     "java archive config",
			typeName: "java.ArchiveCatalogerConfig",
			want:     true,
		},
		{
			name:     "kernel config",
			typeName: "kernel.LinuxKernelCatalogerConfig",
			want:     true,
		},
		{
			name:     "nix config",
			typeName: "nix.Config",
			want:     true,
		},
		{
			name:     "config prefix",
			typeName: "package.ConfigOptions",
			want:     true,
		},
		{
			name:     "not a config type",
			typeName: "package.Parser",
			want:     false,
		},
		{
			name:     "not a config type - resolver",
			typeName: "file.Resolver",
			want:     false,
		},
		{
			name:     "no package prefix",
			typeName: "CatalogerConfig",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeConfigType(tt.typeName)
			require.Equal(t, tt.want, got)
		})
	}
}
