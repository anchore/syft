package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinkCatalogersToConfigsFromPath(t *testing.T) {
	tests := []struct {
		name             string
		fixturePath      string
		expectedLinkages map[string]string
		wantErr          require.ErrorAssertionFunc
	}{
		{
			name:        "simple generic cataloger with local config",
			fixturePath: "simple-generic-cataloger",
			expectedLinkages: map[string]string{
				"go-module-cataloger": "golang.CatalogerConfig",
			},
		},
		{
			name:        "cataloger name from constant",
			fixturePath: "cataloger-with-constant",
			expectedLinkages: map[string]string{
				"python-package-cataloger": "python.CatalogerConfig",
			},
		},
		{
			name:        "custom cataloger with Name() in same file",
			fixturePath: "custom-cataloger-same-file",
			expectedLinkages: map[string]string{
				"java-pom-cataloger": "java.ArchiveCatalogerConfig",
			},
		},
		{
			name:             "custom cataloger with Name() in different file - not detected",
			fixturePath:      "custom-cataloger-different-file",
			expectedLinkages: map[string]string{
				// empty - current limitation, cannot detect cross-file Names
			},
		},
		{
			name:        "cataloger without config parameter",
			fixturePath: "no-config-cataloger",
			expectedLinkages: map[string]string{
				"javascript-cataloger": "", // empty string means no config
			},
		},
		{
			name:        "imported config type",
			fixturePath: "imported-config-type",
			expectedLinkages: map[string]string{
				"linux-kernel-cataloger": "kernel.LinuxKernelCatalogerConfig",
			},
		},
		{
			name:        "non-config first parameter",
			fixturePath: "non-config-first-param",
			expectedLinkages: map[string]string{
				"binary-cataloger": "", // Parser not a config type
			},
		},
		{
			name:        "conflicting cataloger names",
			fixturePath: "conflicting-names",
			wantErr:     require.Error,
		},
		{
			name:        "mixed naming patterns",
			fixturePath: "mixed-naming-patterns",
			expectedLinkages: map[string]string{
				"ruby-cataloger": "ruby.Config",
			},
		},
		{
			name:        "selector expression config",
			fixturePath: "selector-expression-config",
			expectedLinkages: map[string]string{
				"rust-cataloger": "rust.CatalogerConfig",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			fixtureDir := filepath.Join("testdata", "cataloger", tt.fixturePath)
			catalogerRoot := filepath.Join(fixtureDir, "cataloger")
			linkages, err := LinkCatalogersToConfigsFromPath(catalogerRoot, fixtureDir)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			require.Equal(t, tt.expectedLinkages, linkages)
		})
	}
}

func TestExtractConfigTypeName(t *testing.T) {
	tests := []struct {
		name             string
		fixturePath      string
		catalogerName    string
		expectedConfig   string
		expectedNoConfig bool
	}{
		{
			name:           "golang config",
			fixturePath:    "simple-generic-cataloger",
			catalogerName:  "go-module-cataloger",
			expectedConfig: "golang.CatalogerConfig",
		},
		{
			name:           "python config with constant",
			fixturePath:    "cataloger-with-constant",
			catalogerName:  "python-package-cataloger",
			expectedConfig: "python.CatalogerConfig",
		},
		{
			name:           "java archive config same file",
			fixturePath:    "custom-cataloger-same-file",
			catalogerName:  "java-pom-cataloger",
			expectedConfig: "java.ArchiveCatalogerConfig",
		},
		{
			name:           "kernel config imported type",
			fixturePath:    "imported-config-type",
			catalogerName:  "linux-kernel-cataloger",
			expectedConfig: "kernel.LinuxKernelCatalogerConfig",
		},
		{
			name:             "javascript - no config",
			fixturePath:      "no-config-cataloger",
			catalogerName:    "javascript-cataloger",
			expectedNoConfig: true,
		},
		{
			name:           "ruby with mixed naming",
			fixturePath:    "mixed-naming-patterns",
			catalogerName:  "ruby-cataloger",
			expectedConfig: "ruby.Config",
		},
		{
			name:           "rust with selector expression",
			fixturePath:    "selector-expression-config",
			catalogerName:  "rust-cataloger",
			expectedConfig: "rust.CatalogerConfig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureDir := filepath.Join("testdata", "cataloger", tt.fixturePath)
			catalogerRoot := filepath.Join(fixtureDir, "cataloger")
			linkages, err := LinkCatalogersToConfigsFromPath(catalogerRoot, fixtureDir)
			require.NoError(t, err)

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

func TestExtractReceiverTypeName(t *testing.T) {
	tests := []struct {
		name     string
		receiver string // receiver code snippet
		want     string
	}{
		{
			name:     "value receiver",
			receiver: "func (c Cataloger) Name() string { return \"\" }",
			want:     "Cataloger",
		},
		{
			name:     "pointer receiver",
			receiver: "func (c *Cataloger) Name() string { return \"\" }",
			want:     "Cataloger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// parse the function to get the receiver type
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "", "package test\n"+tt.receiver, 0)
			require.NoError(t, err)

			// extract the function declaration
			require.Len(t, file.Decls, 1)
			funcDecl, ok := file.Decls[0].(*ast.FuncDecl)
			require.True(t, ok)

			// get receiver type
			var recvType ast.Expr
			if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
				recvType = funcDecl.Recv.List[0].Type
			}

			got := extractReceiverTypeName(recvType)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractConfigTypeNameHelper(t *testing.T) {
	tests := []struct {
		name             string
		funcSig          string // function signature with parameter
		localPackageName string
		want             string
	}{
		{
			name:             "local type",
			funcSig:          "func New(cfg CatalogerConfig) pkg.Cataloger { return nil }",
			localPackageName: "python",
			want:             "python.CatalogerConfig",
		},
		{
			name:             "imported type",
			funcSig:          "func New(cfg java.ArchiveCatalogerConfig) pkg.Cataloger { return nil }",
			localPackageName: "python",
			want:             "java.ArchiveCatalogerConfig",
		},
		{
			name:             "imported type - kernel package",
			funcSig:          "func New(cfg kernel.LinuxKernelCatalogerConfig) pkg.Cataloger { return nil }",
			localPackageName: "other",
			want:             "kernel.LinuxKernelCatalogerConfig",
		},
		{
			name:             "no parameters",
			funcSig:          "func New() pkg.Cataloger { return nil }",
			localPackageName: "python",
			want:             "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// parse the function to get parameter type
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "", "package test\n"+tt.funcSig, 0)
			require.NoError(t, err)

			// extract the function declaration
			require.Len(t, file.Decls, 1)
			funcDecl, ok := file.Decls[0].(*ast.FuncDecl)
			require.True(t, ok)

			// get first parameter type
			var paramType ast.Expr
			if funcDecl.Type.Params != nil && len(funcDecl.Type.Params.List) > 0 {
				paramType = funcDecl.Type.Params.List[0].Type
			}

			got := extractConfigTypeName(paramType, tt.localPackageName)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractReturnTypeName(t *testing.T) {
	tests := []struct {
		name    string
		funcDef string // complete function definition
		want    string
	}{
		{
			name: "pointer to composite literal",
			funcDef: `func New() pkg.Cataloger {
				return &javaCataloger{name: "test"}
			}`,
			want: "javaCataloger",
		},
		{
			name: "composite literal",
			funcDef: `func New() pkg.Cataloger {
				return pythonCataloger{name: "test"}
			}`,
			want: "pythonCataloger",
		},
		{
			name: "variable return",
			funcDef: `func New() pkg.Cataloger {
				c := &Cataloger{}
				return c
			}`,
			want: "",
		},
		{
			name: "nil return",
			funcDef: `func New() pkg.Cataloger {
				return nil
			}`,
			want: "",
		},
		{
			name:    "empty function body",
			funcDef: `func New() pkg.Cataloger {}`,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// parse the function
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "", "package test\n"+tt.funcDef, 0)
			require.NoError(t, err)

			// extract the function declaration
			require.Len(t, file.Decls, 1)
			funcDecl, ok := file.Decls[0].(*ast.FuncDecl)
			require.True(t, ok)

			got := extractReturnTypeName(funcDecl)
			require.Equal(t, tt.want, got)
		})
	}
}
