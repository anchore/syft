package main

import (
	"go/ast"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities/internal"
)

func TestDiscoverConfigs(t *testing.T) {
	tests := []struct {
		name            string
		fixturePath     string
		expectedConfigs []string
		verifyConfig    func(t *testing.T, configs map[string]ConfigInfo)
	}{
		{
			name:        "simple config with annotations",
			fixturePath: "simple-config",
			expectedConfigs: []string{
				"golang.CatalogerConfig",
			},
			verifyConfig: func(t *testing.T, configs map[string]ConfigInfo) {
				golangConfig := configs["golang.CatalogerConfig"]
				require.Equal(t, "golang", golangConfig.PackageName)
				require.Equal(t, "CatalogerConfig", golangConfig.StructName)
				require.Len(t, golangConfig.Fields, 3, "should have 3 annotated fields")

				// verify specific field
				var foundSearchLocalModCache bool
				for _, field := range golangConfig.Fields {
					if field.Name == "SearchLocalModCacheLicenses" {
						foundSearchLocalModCache = true
						require.Equal(t, "bool", field.Type)
						require.Equal(t, "golang.search-local-mod-cache-licenses", field.AppKey)
						require.Contains(t, field.Description, "searching for go package licenses")
					}
				}
				require.True(t, foundSearchLocalModCache, "should find SearchLocalModCacheLicenses field")
			},
		},
		{
			name:        "nested config struct",
			fixturePath: "nested-config",
			expectedConfigs: []string{
				"golang.CatalogerConfig",
				"golang.MainModuleVersionConfig",
			},
			verifyConfig: func(t *testing.T, configs map[string]ConfigInfo) {
				// verify main config
				golangConfig := configs["golang.CatalogerConfig"]
				require.Equal(t, "golang", golangConfig.PackageName)
				require.Equal(t, "CatalogerConfig", golangConfig.StructName)

				// verify nested config
				mainModuleConfig := configs["golang.MainModuleVersionConfig"]
				require.Equal(t, "golang", mainModuleConfig.PackageName)
				require.Equal(t, "MainModuleVersionConfig", mainModuleConfig.StructName)
				require.Len(t, mainModuleConfig.Fields, 2, "should have 2 annotated fields")

				// check for specific nested field
				var foundFromLDFlags bool
				for _, field := range mainModuleConfig.Fields {
					if field.Name == "FromLDFlags" {
						foundFromLDFlags = true
						require.Equal(t, "bool", field.Type)
						require.Equal(t, "golang.main-module-version.from-ld-flags", field.AppKey)
						require.Contains(t, field.Description, "extract version from LD flags")
					}
				}
				require.True(t, foundFromLDFlags, "should find FromLDFlags field")
			},
		},
		{
			name:        "multiple configs in different packages",
			fixturePath: "multiple-configs",
			expectedConfigs: []string{
				"python.CatalogerConfig",
				"java.ArchiveCatalogerConfig",
			},
			verifyConfig: func(t *testing.T, configs map[string]ConfigInfo) {
				// verify python config
				pythonConfig := configs["python.CatalogerConfig"]
				require.Equal(t, "python", pythonConfig.PackageName)
				require.Len(t, pythonConfig.Fields, 1)

				// verify java config
				javaConfig := configs["java.ArchiveCatalogerConfig"]
				require.Equal(t, "java", javaConfig.PackageName)
				require.Len(t, javaConfig.Fields, 1)
			},
		},
		{
			name:            "config without annotations",
			fixturePath:     "no-annotations",
			expectedConfigs: []string{},
			verifyConfig: func(t *testing.T, configs map[string]ConfigInfo) {
				// should not discover any configs without annotations
				require.Empty(t, configs, "should not discover configs without app-config annotations")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureDir := filepath.Join("testdata", "config-discovery", tt.fixturePath, "cataloger")
			configs, err := DiscoverConfigsFromPath(fixtureDir)
			require.NoError(t, err)

			// Debug: log what was discovered
			t.Logf("Discovered %d configs:", len(configs))
			for key, config := range configs {
				t.Logf("  %s: %d fields", key, len(config.Fields))
			}

			// verify expected configs were discovered
			for _, expected := range tt.expectedConfigs {
				config, ok := configs[expected]
				require.True(t, ok, "should discover config: %s", expected)
				require.NotEmpty(t, config.Fields, "config %s should have fields", expected)
				require.Equal(t, expected, config.PackageName+"."+config.StructName)
			}

			// run custom verification
			if tt.verifyConfig != nil {
				tt.verifyConfig(t, configs)
			}
		})
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

func TestFormatFieldType(t *testing.T) {
	tests := []struct {
		name string
		expr ast.Expr
		want string
	}{
		{
			name: "basic identifier - string",
			expr: &ast.Ident{Name: "string"},
			want: "string",
		},
		{
			name: "basic identifier - bool",
			expr: &ast.Ident{Name: "bool"},
			want: "bool",
		},
		{
			name: "basic identifier - int",
			expr: &ast.Ident{Name: "int"},
			want: "int",
		},
		{
			name: "selector expression - package.Type",
			expr: &ast.SelectorExpr{
				X:   &ast.Ident{Name: "time"},
				Sel: &ast.Ident{Name: "Time"},
			},
			want: "time.Time",
		},
		{
			name: "selector expression - cataloging.Config",
			expr: &ast.SelectorExpr{
				X:   &ast.Ident{Name: "cataloging"},
				Sel: &ast.Ident{Name: "ArchiveSearchConfig"},
			},
			want: "cataloging.ArchiveSearchConfig",
		},
		{
			name: "array of strings",
			expr: &ast.ArrayType{
				Elt: &ast.Ident{Name: "string"},
			},
			want: "[]string",
		},
		{
			name: "array of ints",
			expr: &ast.ArrayType{
				Elt: &ast.Ident{Name: "int"},
			},
			want: "[]int",
		},
		{
			name: "map[string]bool",
			expr: &ast.MapType{
				Key:   &ast.Ident{Name: "string"},
				Value: &ast.Ident{Name: "bool"},
			},
			want: "map[string]bool",
		},
		{
			name: "map[string]int",
			expr: &ast.MapType{
				Key:   &ast.Ident{Name: "string"},
				Value: &ast.Ident{Name: "int"},
			},
			want: "map[string]int",
		},
		{
			name: "pointer to type",
			expr: &ast.StarExpr{
				X: &ast.Ident{Name: "Config"},
			},
			want: "*Config",
		},
		{
			name: "pointer to selector",
			expr: &ast.StarExpr{
				X: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "time"},
					Sel: &ast.Ident{Name: "Time"},
				},
			},
			want: "*time.Time",
		},
		{
			name: "interface{}",
			expr: &ast.InterfaceType{
				Methods: &ast.FieldList{},
			},
			want: "interface{}",
		},
		{
			name: "nested array of arrays",
			expr: &ast.ArrayType{
				Elt: &ast.ArrayType{
					Elt: &ast.Ident{Name: "string"},
				},
			},
			want: "[][]string",
		},
		{
			name: "map with array value",
			expr: &ast.MapType{
				Key: &ast.Ident{Name: "string"},
				Value: &ast.ArrayType{
					Elt: &ast.Ident{Name: "int"},
				},
			},
			want: "map[string][]int",
		},
		{
			name: "pointer to array",
			expr: &ast.StarExpr{
				X: &ast.ArrayType{
					Elt: &ast.Ident{Name: "string"},
				},
			},
			want: "*[]string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFieldType(tt.expr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractFieldComments(t *testing.T) {
	tests := []struct {
		name            string
		commentGroup    *ast.CommentGroup
		wantDescription string
		wantAppKey      string
	}{
		{
			name:            "nil comment group",
			commentGroup:    nil,
			wantDescription: "",
			wantAppKey:      "",
		},
		{
			name: "empty comment group",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{},
			},
			wantDescription: "",
			wantAppKey:      "",
		},
		{
			name: "app-config annotation only",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "// app-config: golang.search-local-mod-cache-licenses"},
				},
			},
			wantDescription: "",
			wantAppKey:      "golang.search-local-mod-cache-licenses",
		},
		{
			name: "description only",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "// enable searching for go package licenses in the local mod cache"},
				},
			},
			wantDescription: "enable searching for go package licenses in the local mod cache",
			wantAppKey:      "",
		},
		{
			name: "description and app-config",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "// enable searching for go package licenses in the local mod cache"},
					{Text: "// app-config: golang.search-local-mod-cache-licenses"},
				},
			},
			wantDescription: "enable searching for go package licenses in the local mod cache",
			wantAppKey:      "golang.search-local-mod-cache-licenses",
		},
		{
			name: "app-config before description",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "// app-config: golang.search-local-mod-cache-licenses"},
					{Text: "// enable searching for go package licenses in the local mod cache"},
				},
			},
			wantDescription: "enable searching for go package licenses in the local mod cache",
			wantAppKey:      "golang.search-local-mod-cache-licenses",
		},
		{
			name: "multi-line description",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "// this is the first line of the description."},
					{Text: "// this is the second line of the description."},
					{Text: "// app-config: test.multi-line"},
				},
			},
			wantDescription: "this is the first line of the description. this is the second line of the description.",
			wantAppKey:      "test.multi-line",
		},
		{
			name: "app-config with extra whitespace",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "//   app-config:   golang.test-key  "},
				},
			},
			wantDescription: "",
			wantAppKey:      "golang.test-key",
		},
		{
			name: "description with special characters",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "// enable searching for Go's package licenses (*.mod files)"},
					{Text: "// app-config: golang.search"},
				},
			},
			wantDescription: "enable searching for Go's package licenses (*.mod files)",
			wantAppKey:      "golang.search",
		},
		{
			name: "comment with empty lines",
			commentGroup: &ast.CommentGroup{
				List: []*ast.Comment{
					{Text: "// first line"},
					{Text: "//"},
					{Text: "// second line"},
					{Text: "// app-config: test.key"},
				},
			},
			wantDescription: "first line second line",
			wantAppKey:      "test.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDescription, gotAppKey := extractFieldComments(tt.commentGroup)
			require.Equal(t, tt.wantDescription, gotDescription)
			require.Equal(t, tt.wantAppKey, gotAppKey)
		})
	}
}

func TestDiscoverAllowedConfigStructs(t *testing.T) {
	repoRoot, err := internal.RepoRoot()
	require.NoError(t, err)

	allowedConfigs, err := DiscoverAllowedConfigStructs(repoRoot)
	require.NoError(t, err)

	// verify we found multiple config types
	require.NotEmpty(t, allowedConfigs, "should discover at least one allowed config type")

	// verify specific config types that should be in pkgcataloging.Config
	expectedConfigs := []string{
		"golang.CatalogerConfig",
		"java.ArchiveCatalogerConfig",
		"python.CatalogerConfig",
		"dotnet.CatalogerConfig",
		"kernel.LinuxKernelCatalogerConfig",
		"javascript.CatalogerConfig",
	}

	for _, expected := range expectedConfigs {
		require.True(t, allowedConfigs[expected], "should find %s in allowed configs", expected)
	}

	// log all discovered configs for manual inspection
	t.Logf("Discovered %d allowed config types:", len(allowedConfigs))
	for configType := range allowedConfigs {
		t.Logf("  - %s", configType)
	}
}
