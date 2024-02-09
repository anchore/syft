package integration

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_packageCatalogerExports(t *testing.T) {
	// sanity check that we are actually finding exports

	exports := packageCatalogerExports(t)
	require.NotEmpty(t, exports)

	expectAtLeast := map[string]*strset.Set{
		"golang": strset.New("NewGoModuleFileCataloger", "NewGoModuleBinaryCataloger", "CatalogerConfig", "DefaultCatalogerConfig"),
	}

	for pkg, expected := range expectAtLeast {
		actual, ok := exports[pkg]
		require.True(t, ok, pkg)
		if !assert.True(t, actual.Names().IsSubset(expected), pkg) {
			t.Logf("missing: %s", strset.SymmetricDifference(expected, actual.Names()))
		}
	}

}

func Test_validatePackageCatalogerExport(t *testing.T) {
	cases := []struct {
		name    string
		export  exportToken
		wantErr assert.ErrorAssertionFunc
	}{
		// valid...
		{
			name: "valid constructor",
			export: exportToken{
				Name:          "NewFooCataloger",
				Type:          "*ast.FuncType",
				SignatureSize: 1,
				ReturnTypeNames: []string{
					"pkg.Cataloger",
				},
			},
		},
		{
			name: "valid default config",
			export: exportToken{
				Name:          "DefaultFooConfig",
				Type:          "*ast.FuncType",
				SignatureSize: 0,
			},
		},
		{
			name: "valid config",
			export: exportToken{
				Name: "FooConfig",
				Type: "*ast.StructType",
			},
		},
		// invalid...
		{
			name: "constructor that returns a concrete type",
			export: exportToken{
				Name:          "NewFooCataloger",
				Type:          "*ast.FuncType",
				SignatureSize: 1,
				ReturnTypeNames: []string{
					"*generic.Cataloger",
				},
			},
			wantErr: assert.Error,
		},
		{
			name: "struct with constructor name",
			export: exportToken{
				Name: "NewFooCataloger",
				Type: "*ast.StructType",
			},
			wantErr: assert.Error,
		},
		{
			name: "struct with default config fn name",
			export: exportToken{
				Name: "DefaultFooConfig",
				Type: "*ast.StructType",
			},
			wantErr: assert.Error,
		},
		{
			name: "fn with struct name",
			export: exportToken{
				Name: "FooConfig",
				Type: "*ast.FuncType",
			},
			wantErr: assert.Error,
		},
		{
			name: "default config with parameters",
			export: exportToken{
				Name:          "DefaultFooConfig",
				Type:          "*ast.FuncType",
				SignatureSize: 1,
			},
			wantErr: assert.Error,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.wantErr == nil {
				c.wantErr = assert.NoError
			}
			err := validatePackageCatalogerExport(t, "test", c.export)
			c.wantErr(t, err)
		})
	}
}

func Test_PackageCatalogerConventions(t *testing.T) {
	// look at each package in syft/pkg/cataloger...
	// we want to make certain that only the following things are exported from the package:
	// - function matching New*Cataloger (e.g. NewAptCataloger)
	// - function matching Default*Config
	// - struct matching *Config
	//
	// anything else that is exported should result in the test failing.
	// note: this is meant to apply to things in static space, not methods on structs or within interfaces.
	//
	// this additionally ensures that:
	// - any config struct has a Default*Config function to pair with it.
	// - all cataloger constructors return pkg.Cataloger interface instead of a concrete type

	exportsPerPackage := packageCatalogerExports(t)

	//for debugging purposes...
	//for pkg, exports := range exportsPerPackage {
	//	t.Log(pkg)
	//	for _, export := range exports {
	//		t.Logf("  %#v", export)
	//	}
	//}

	for pkg, exports := range exportsPerPackage {
		for _, export := range exports.List() {
			// assert the export name is valid...
			assert.NoError(t, validatePackageCatalogerExport(t, pkg, export))

			// assert that config structs have a Default*Config functions to pair with them...
			if strings.Contains(export.Name, "Config") && !strings.Contains(export.Name, "Default") {
				// this is a config struct, make certain there is a pairing with a Default*Config function
				assert.True(t, exports.Has("Default"+export.Name), "cataloger config struct %q in pkg %q must have a 'Default%s' function", export.Name, pkg, export.Name)
			}
		}
	}
}

func validatePackageCatalogerExport(t *testing.T, pkg string, export exportToken) error {

	constructorMatches, err := doublestar.Match("New*Cataloger", export.Name)
	require.NoError(t, err)

	defaultConfigMatches, err := doublestar.Match("Default*Config", export.Name)
	require.NoError(t, err)

	configMatches, err := doublestar.Match("*Config", export.Name)
	require.NoError(t, err)

	switch {
	case constructorMatches:
		if !export.isFunction() {
			return fmt.Errorf("constructor convention used for non-function in pkg=%q: %#v", pkg, export)
		}

		returnTypes := strset.New(export.ReturnTypeNames...)
		if !returnTypes.Has("pkg.Cataloger") {
			return fmt.Errorf("constructor convention is to return pkg.Cataloger and not concrete types. pkg=%q constructor=%q types=%+v", pkg, export.Name, strings.Join(export.ReturnTypeNames, ","))
		}

	case defaultConfigMatches:
		if !export.isFunction() {
			return fmt.Errorf("default config convention used for non-function in pkg=%q: %#v", pkg, export)
		}
		if export.SignatureSize != 0 {
			return fmt.Errorf("default config convention used for non-zero signature size in pkg=%q: %#v", pkg, export)
		}
	case configMatches:
		if !export.isStruct() {
			return fmt.Errorf("config convention used for non-struct in pkg=%q: %#v", pkg, export)
		}
	default:
		return fmt.Errorf("unexpected export in pkg=%q: %#v", pkg, export)
	}
	return nil
}

type exportToken struct {
	Name            string
	Type            string
	SignatureSize   int
	ReturnTypeNames []string
}

func (e exportToken) isFunction() bool {
	return strings.Contains(e.Type, "ast.FuncType")
}

func (e exportToken) isStruct() bool {
	return strings.Contains(e.Type, "ast.StructType")
}

type exportTokenSet map[string]exportToken

func (s exportTokenSet) Names() *strset.Set {
	set := strset.New()
	for k := range s {
		set.Add(k)
	}
	return set
}

func (s exportTokenSet) Has(name string) bool {
	_, ok := s[name]
	return ok
}

func (s exportTokenSet) Add(tokens ...exportToken) {
	for _, t := range tokens {
		if _, ok := s[t.Name]; ok {
			panic("duplicate token name: " + t.Name)
		}
		s[t.Name] = t
	}
}

func (s exportTokenSet) Remove(names ...string) {
	for _, name := range names {
		delete(s, name)
	}
}

func (s exportTokenSet) List() []exportToken {
	var tokens []exportToken
	for _, t := range s {
		tokens = append(tokens, t)
	}
	return tokens
}

func packageCatalogerExports(t *testing.T) map[string]exportTokenSet {
	t.Helper()

	catalogerPath := filepath.Join(repoRoot(t), "syft", "pkg", "cataloger")

	ignorePaths := []string{
		filepath.Join(catalogerPath, "common"),
		filepath.Join(catalogerPath, "generic"),
	}

	exportsPerPackage := make(map[string]exportTokenSet)

	err := filepath.Walk(catalogerPath, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)

		if info.IsDir() ||
			!strings.HasSuffix(info.Name(), ".go") ||
			strings.HasSuffix(info.Name(), "_test.go") ||
			strings.Contains(path, "test-fixtures") ||
			strings.Contains(path, "internal") {
			return nil
		}

		for _, ignorePath := range ignorePaths {
			if strings.Contains(path, ignorePath) {
				return nil
			}
		}

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		require.NoError(t, err)

		pkg := node.Name.Name
		for _, f := range node.Decls {
			switch decl := f.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.IsExported() {
							if _, ok := exportsPerPackage[pkg]; !ok {
								exportsPerPackage[pkg] = make(exportTokenSet)
							}
							exportsPerPackage[pkg].Add(exportToken{
								Name: spec.Name.Name,
								Type: reflect.TypeOf(spec.Type).String(),
							})
						}
					}
				}
			case *ast.FuncDecl:
				if decl.Recv == nil && decl.Name.IsExported() {
					var returnTypes []string
					if decl.Type.Results != nil {
						for _, field := range decl.Type.Results.List {
							// TODO: there is probably a better way to extract the specific type name
							//ty := strings.Join(strings.Split(fmt.Sprint(field.Type), " "), ".")
							ty := types.ExprString(field.Type)

							returnTypes = append(returnTypes, ty)
						}
					}

					if _, ok := exportsPerPackage[pkg]; !ok {
						exportsPerPackage[pkg] = make(exportTokenSet)
					}
					exportsPerPackage[pkg].Add(exportToken{
						Name:            decl.Name.Name,
						Type:            reflect.TypeOf(decl.Type).String(),
						SignatureSize:   len(decl.Type.Params.List),
						ReturnTypeNames: returnTypes,
					})
				}
			}
		}

		return nil
	})

	require.NoError(t, err)

	// remove exceptions
	// these are known violations to the common convention that are allowed.
	if vs, ok := exportsPerPackage["binary"]; ok {
		vs.Remove("Classifier", "EvidenceMatcher", "FileContentsVersionMatcher", "DefaultClassifiers")
	}

	return exportsPerPackage
}
