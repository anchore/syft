package integration

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
)

func TestAllPackageCatalogersReachableInTasks(t *testing.T) {
	// we want to see if we can get a task for all package catalogers. This is a bit tricky since we
	// don't have a nice way to find all cataloger names in the codebase. Instead, we'll look at the
	// count of unique task names from the package task factory set and compare that with the known constructors
	// from a source analysis... they should match.

	// additionally, at this time they should either have a "directory" or "image" tag as well. If there is no tag
	// on a cataloger task then the test should fail.

	taskFactories := task.DefaultPackageTaskFactories()
	taskTagsByName := make(map[string][]string)
	for _, factory := range taskFactories {
		tsk := factory(task.DefaultCatalogingFactoryConfig())
		if taskTagsByName[tsk.Name()] != nil {
			t.Fatalf("duplicate task name: %q", tsk.Name())
		}

		require.NotNil(t, tsk)
		if sel, ok := tsk.(task.Selector); ok {
			taskTagsByName[tsk.Name()] = sel.Selectors()
		} else {
			taskTagsByName[tsk.Name()] = []string{}
		}
	}

	var constructorCount int
	constructorsPerPackage := getCatalogerConstructors(t)
	for _, constructors := range constructorsPerPackage {
		constructorCount += constructors.Size()
	}

	assert.Equal(t, len(taskTagsByName), constructorCount, "mismatch in number of cataloger constructors and task names")

	for taskName, tags := range taskTagsByName {
		if taskName == "sbom-cataloger" {
			continue // this is a special case
		}
		if !strset.New(tags...).HasAny(pkgcataloging.ImageTag, pkgcataloging.DirectoryTag) {
			t.Errorf("task %q is missing 'directory' or 'image' a tag", taskName)
		}
	}

}

func TestAllPackageCatalogersRepresentedInSource(t *testing.T) {
	// find all functions in syft/pkg/cataloger/** that either:
	// - match the name glob "New*Cataloger"
	// - are in cataloger.go and match the name glob "New*"
	//
	// Then:
	// - keep track of all packages with cataloger constructors
	// - keep track of all constructors
	constructorsPerPackage := getCatalogerConstructors(t)

	// look at the source file in internal/task/package_tasks.go:
	// - ensure all go packages that have constructors are imported
	// - ensure there is a reference to all package constructors
	assertAllPackageCatalogersRepresented(t, constructorsPerPackage)
}

func getCatalogerConstructors(t *testing.T) map[string]*strset.Set {
	t.Helper()
	root := repoRoot(t)
	catalogerPath := filepath.Join(root, "syft", "pkg", "cataloger")

	constructorsPerPackage := make(map[string]*strset.Set)

	err := filepath.Walk(catalogerPath, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)

		// ignore directories and test files...
		if info.IsDir() || strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		partialResults := getConstructorsFromExpectedFile(t, path, info)

		constructorsPerPackage = mergeConstructors(constructorsPerPackage, partialResults)

		partialResults = getCatalogerConstructorsFromPackage(t, path, info)

		constructorsPerPackage = mergeConstructors(constructorsPerPackage, partialResults)

		return nil
	})

	require.NoError(t, err)

	// remove some exceptions
	delete(constructorsPerPackage, "generic") // this is not an actual cataloger

	return constructorsPerPackage
}

func getConstructorsFromExpectedFile(t *testing.T, path string, info os.FileInfo) map[string][]string {
	constructorsPerPackage := make(map[string][]string)

	if !strings.HasSuffix(info.Name(), "cataloger.go") && !strings.HasSuffix(info.Name(), "catalogers.go") {
		return nil
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	require.NoError(t, err)

	for _, f := range node.Decls {
		fn, ok := f.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "New") {
			continue
		}

		pkg := node.Name.Name
		constructorsPerPackage[pkg] = append(constructorsPerPackage[pkg], fn.Name.Name)
	}

	return constructorsPerPackage
}

func getCatalogerConstructorsFromPackage(t *testing.T, path string, info os.FileInfo) map[string][]string {
	constructorsPerPackage := make(map[string][]string)

	if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
		return nil
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	require.NoError(t, err)

	for _, f := range node.Decls {
		fn, ok := f.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "New") || !strings.HasSuffix(fn.Name.Name, "Cataloger") {
			continue
		}

		pkg := node.Name.Name
		constructorsPerPackage[pkg] = append(constructorsPerPackage[pkg], fn.Name.Name)
	}

	return constructorsPerPackage
}

func assertAllPackageCatalogersRepresented(t *testing.T, constructorsPerPackage map[string]*strset.Set) {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "task", "package_tasks.go"))
	require.NoError(t, err)

	// ensure all packages (keys) are represented in the package_tasks.go file
	for pkg, constructors := range constructorsPerPackage {
		if !assert.True(t, bytes.Contains(contents, []byte(pkg)), "missing package %q", pkg) {
			continue
		}
		for _, constructor := range constructors.List() {
			assert.True(t, bytes.Contains(contents, []byte(constructor)), "missing constructor %q for package %q", constructor, pkg)
		}
	}

}

func repoRoot(t testing.TB) string {
	t.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		t.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}

func mergeConstructors(constructorsPerPackage map[string]*strset.Set, partialResults map[string][]string) map[string]*strset.Set {
	for pkg, constructors := range partialResults {
		if _, ok := constructorsPerPackage[pkg]; !ok {
			constructorsPerPackage[pkg] = strset.New()
		}
		constructorsPerPackage[pkg].Add(constructors...)
	}

	return constructorsPerPackage
}
