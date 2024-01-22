package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	// this additionally ensures that any config struct has a Default*Config function to pair with it.

	exportsPerPackage := packageCatalogerExports(t)

	//for debugging purposes...
	//for pkg, exports := range exportsPerPackage {
	//	t.Log(pkg)
	//	for _, export := range exports.List() {
	//		t.Logf("  %s", export)
	//	}
	//}

	for pkg, exports := range exportsPerPackage {
		for _, export := range exports.List() {
			// assert the export name is valid...
			validatePackageCatalogerExport(t, pkg, export)

			// assert that config structs have a Default*Config functions to pair with them...
			if strings.Contains(export, "Config") && !strings.Contains(export, "Default") {
				// this is a config struct, make certain there is a pairing with a Default*Config function
				assert.True(t, exports.Has("Default"+export), "cataloger config struct %q in pkg %q must have a 'Default%s' function", export, pkg, export)
			}
		}
	}
}

func validatePackageCatalogerExport(t *testing.T, pkg, export string) {
	t.Helper()

	constructorMatches, err := doublestar.Match("New*Cataloger", export)
	require.NoError(t, err)

	defaultConfigMatches, err := doublestar.Match("Default*Config", export)
	require.NoError(t, err)

	configMatches, err := doublestar.Match("*Config", export)
	require.NoError(t, err)

	switch {
	case constructorMatches, defaultConfigMatches, configMatches:
		return
	}

	t.Errorf("unexpected export in pkg=%q: %q", pkg, export)
}

func packageCatalogerExports(t *testing.T) map[string]*strset.Set {
	t.Helper()
	root := repoRoot(t)
	catalogerPath := filepath.Join(root, "syft", "pkg", "cataloger")

	ignorePaths := []string{
		filepath.Join(catalogerPath, "common"),
		filepath.Join(catalogerPath, "generic"),
	}

	exportsPerPackage := make(map[string]*strset.Set)

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
		if _, ok := exportsPerPackage[pkg]; !ok {
			exportsPerPackage[pkg] = strset.New()
		}

		for _, f := range node.Decls {
			switch decl := f.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.IsExported() {
								exportsPerPackage[pkg].Add(name.Name)
							}
						}
					case *ast.TypeSpec:
						if spec.Name.IsExported() {
							exportsPerPackage[pkg].Add(spec.Name.Name)
						}
					}
				}
			case *ast.FuncDecl:
				if decl.Recv == nil && decl.Name.IsExported() {
					exportsPerPackage[pkg].Add(decl.Name.Name)
				}
			}
		}

		return nil
	})

	require.NoError(t, err)

	// remove exceptions
	// these are known violations to the common convention that are allowed.
	if v, ok := exportsPerPackage["binary"]; ok {
		v.Remove("Classifier", "EvidenceMatcher", "FileContentsVersionMatcher", "DefaultClassifiers")
	}

	return exportsPerPackage
}

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
		require.True(t, expected.IsSubset(actual), pkg)
	}

}
