package sourcemetadata

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
)

type FileInfo struct {
	PkgPath string
	File    *ast.File
}

type TypeInfo struct {
	FileInfo *FileInfo
	Spec     *ast.TypeSpec
}

func DiscoverTypes() ([]*TypeInfo, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	modFilePath := path.Join(root, "go.mod")
	data, err := os.ReadFile(modFilePath)
	if err != nil {
		return nil, err
	}
	mod, err := modfile.Parse(modFilePath, data, nil)
	if err != nil {
		return nil, err
	}
	srcImportBase := moduleName(mod)
	if srcImportBase == "" {
		return nil, fmt.Errorf("unable to determine go module name from: %s", modFilePath)
	}
	files, err := filepath.Glob(filepath.Join(root, "syft/source/**/*.go"))
	if err != nil {
		return nil, err
	}
	return findMetadataDefinitions(srcImportBase, root, files...)
}

func moduleName(mod *modfile.File) string {
	if mod == nil || mod.Module == nil {
		return ""
	}
	return mod.Module.Mod.Path
}

func repoRoot() (string, error) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		return "", fmt.Errorf("unable to get abs path to repo root: %w", err)
	}
	return absRepoRoot, nil
}

func compareTypeInfo(a, b *TypeInfo) int {
	v := strings.Compare(a.FileInfo.PkgPath, b.FileInfo.PkgPath)
	if v != 0 {
		return v
	}
	return strings.Compare(a.Spec.Name.String(), b.Spec.Name.String())
}

func findMetadataDefinitions(srcImportBase string, root string, paths ...string) ([]*TypeInfo, error) {
	metadata, err := findTypeDefinitions(srcImportBase, root, paths...)
	if err != nil {
		return nil, err
	}

	// remove structs without Metadata in the name
	metadata = removeFunc(metadata, func(t *TypeInfo) bool {
		return !strings.HasSuffix(t.Spec.Name.String(), "Metadata")
	})

	// any definition that is used within another struct should not be considered a top-level metadata definition
	metadata = removeFunc(metadata, func(t *TypeInfo) bool {
		return isUsedInStructs(metadata, t)
	})

	slices.SortFunc(metadata, compareTypeInfo)

	// note: 3 is a point-in-time gut check. This number could be updated if new metadata definitions are added, but is not required.
	// it is really intended to catch any major issues with the generation process that would generate, say, 0 definitions.
	if len(metadata) < 3 {
		names := reduce(metadata, []string{}, func(prev []string, value *TypeInfo) []string {
			return append(prev, fmt.Sprintf("%s.%s", path.Base(value.FileInfo.PkgPath), nameOf(value.Spec.Name)))
		})
		return nil, fmt.Errorf("not enough metadata definitions found (discovered %d: %v)", len(metadata), names)
	}

	return metadata, nil
}

func findTypeDefinitions(srcImportBase string, root string, paths ...string) ([]*TypeInfo, error) {
	var topLevelStructs []*TypeInfo
	for _, file := range paths {
		f, typeSpecs, err := findTopLevelStructs(file)
		if err != nil {
			return nil, err
		}

		pkgPath := strings.TrimLeft(path.Dir(strings.TrimPrefix(file, root)), "/\\")
		fi := &FileInfo{
			PkgPath: strings.ReplaceAll(fmt.Sprintf("%s/%s", srcImportBase, pkgPath), "\\", "/"),
			File:    f,
		}

		for _, typeSpec := range typeSpecs {
			topLevelStructs = append(topLevelStructs, &TypeInfo{
				FileInfo: fi,
				Spec:     typeSpec,
			})
		}

		// useful for debugging...
		fmt.Println(file)
		fmt.Printf("Package: %v \n", fi.PkgPath)
		fmt.Printf("Specs: %v \n", reduce(typeSpecs, nil, func(prev []string, value *ast.TypeSpec) []string {
			return append(prev, value.Name.String())
		}))
		fmt.Println()
	}

	slices.SortFunc(topLevelStructs, compareTypeInfo)

	return topLevelStructs, nil
}

func removeFunc[T any](values []T, remove func(T) bool) []T {
	var out []T
	for _, t := range values {
		if remove(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func findTopLevelStructs(file string) (*ast.File, []*ast.TypeSpec, error) {
	// set up the parser
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, file, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}

	var typeSpecs []*ast.TypeSpec
	for _, decl := range f.Decls {
		// check if the declaration is a type declaration
		spec, ok := decl.(*ast.GenDecl)
		if !ok || spec.Tok != token.TYPE {
			continue
		}

		// loop over all types declared in the type declaration
		for _, typ := range spec.Specs {
			// check if the type is a struct type
			spec, ok := typ.(*ast.TypeSpec)
			if !ok || spec.Type == nil {
				continue
			}

			// only care about exported structs
			if !spec.Name.IsExported() {
				continue
			}

			typeSpecs = append(typeSpecs, spec)
		}
	}
	return f, typeSpecs, nil
}

func isUsedInStructs(topLevelStructs []*TypeInfo, checkIfUsed *TypeInfo) bool {
	for _, s := range topLevelStructs {
		if isUsedInStruct(s, checkIfUsed) {
			return true
		}
	}
	return false
}

func isUsedInStruct(typeInfo *TypeInfo, checkIfUsed *TypeInfo) bool {
	structType, ok := typeInfo.Spec.Type.(*ast.StructType)
	if !ok {
		return false
	}
	used := false
	// recursively find all type names used in the struct type
	for i := range structType.Fields.List {
		// capture names of all the types (not field names)
		fieldType := structType.Fields.List[i].Type
		ast.Inspect(fieldType, func(n ast.Node) bool {
			importPath := typeInfo.FileInfo.PkgPath

			var ident *ast.Ident
			sel, ok := n.(*ast.SelectorExpr)
			if ok {
				name := nameOf(sel.X)
				// find matching import
				for _, imp := range typeInfo.FileInfo.File.Imports {
					impAlias := nameOf(imp.Name)
					impPath := nameOf(imp.Path)
					if impAlias == name || (impAlias == "" && name == path.Base(impPath)) {
						importPath = impPath
						break
					}
				}
				ident = sel.Sel
			} else {
				ident, _ = n.(*ast.Ident)
			}

			if ident == nil || !ident.IsExported() {
				return true // continue inspecting
			}

			if importPath == checkIfUsed.FileInfo.PkgPath &&
				ident.Name == checkIfUsed.Spec.Name.Name {
				used = true
				return false // stop inspecting
			}

			return true // continue inspecting
		})
	}

	return used
}

func nameOf(expr ast.Node) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if e == nil {
			return ""
		}
		return e.Name
	case *ast.BasicLit:
		if e == nil {
			return ""
		}
		return strings.Trim(e.Value, `"`)
	}
	return ""
}

func reduce[T any, R any](values []T, initialValue R, reducer func(prev R, value T) R) R {
	for _, v := range values {
		initialValue = reducer(initialValue, v)
	}
	return initialValue
}
