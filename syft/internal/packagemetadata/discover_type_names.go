package packagemetadata

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/scylladb/go-set/strset"
)

// these are names of struct types in the pkg package that are not metadata types (thus should not be in the JSON schema)
var knownNonMetadataTypeNames = strset.New(
	"Package",
	"Collection",
	"License",
	"LicenseSet",
)

// these are names that would be removed due to common convention (e.g. used within another metadata type) but are
// known to be metadata types themselves. Adding to this list will prevent the removal of the type from the schema.
var knownMetadaTypeNames = strset.New(
	"DotnetPortableExecutableEntry",
)

func DiscoverTypeNames() ([]string, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(root, "syft/pkg/*.go"))
	if err != nil {
		return nil, err
	}
	return findMetadataDefinitionNames(files...)
}

func RepoRoot() (string, error) {
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

func findMetadataDefinitionNames(paths ...string) ([]string, error) {
	names := strset.New()
	usedNames := strset.New()
	for _, path := range paths {
		metadataDefinitions, usedTypeNames, err := findMetadataDefinitionNamesInFile(path)
		if err != nil {
			return nil, err
		}

		// useful for debugging...
		// fmt.Println(path)
		// fmt.Println("Defs:", metadataDefinitions)
		// fmt.Println("Used Types:", usedTypeNames)
		// fmt.Println()

		names.Add(metadataDefinitions...)
		usedNames.Add(usedTypeNames...)
	}

	// any definition that is used within another struct should not be considered a top-level metadata definition
	removeNames := strset.Difference(usedNames, knownMetadaTypeNames)
	names.Remove(removeNames.List()...)

	// remove known exceptions, that is, types exported in the pkg Package that are not used
	// in a metadata type but are not metadata types themselves.
	names.Remove("Licenses", "KeyValue")

	strNames := names.List()
	sort.Strings(strNames)

	// note: 35 is a point-in-time gut check. This number could be updated if new metadata definitions are added, but is not required.
	// it is really intended to catch any major issues with the generation process that would generate, say, 0 definitions.
	if len(strNames) < 35 {
		msg := fmt.Sprintf("not enough metadata definitions found (discovered %d)", len(strNames))
		return nil, fmt.Errorf("%v", msg)
	}

	return strNames, nil
}

func findMetadataDefinitionNamesInFile(path string) ([]string, []string, error) {
	// set up the parser
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}

	var metadataDefinitions []string
	var usedTypeNames []string
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

			name := spec.Name.String()

			// only look for exported types
			if !isMetadataTypeCandidate(name) {
				continue
			}

			structType := extractStructType(spec.Type)
			if structType == nil {
				// maybe this is a slice of structs? This is useful (say type KeyValues is []KeyValue)
				structType = extractSliceOfStructType(spec.Type)
				if structType == nil {
					continue
				}
			}

			metadataDefinitions = append(metadataDefinitions, name)
			usedTypeNames = append(usedTypeNames, typeNamesUsedInStruct(structType)...)
		}
	}
	return metadataDefinitions, usedTypeNames, nil
}

func extractSliceOfStructType(exp ast.Expr) *ast.StructType {
	var structType *ast.StructType
	switch ty := exp.(type) {
	case *ast.ArrayType:
		// this is a standard definition:
		// type FooMetadata []BarMetadata
		structType = extractStructType(ty.Elt)
	case *ast.Ident:
		if ty.Obj == nil {
			return nil
		}

		// this might be a type created from another type:
		// type FooMetadata BarMetadata
		// ... but we need to check that the other type definition is a struct type
		typeSpec, ok := ty.Obj.Decl.(*ast.TypeSpec)
		if !ok {
			return nil
		}
		nestedStructType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return nil
		}
		structType = nestedStructType
	}
	return structType
}

func extractStructType(exp ast.Expr) *ast.StructType {
	var structType *ast.StructType
	switch ty := exp.(type) {
	case *ast.StructType:
		// this is a standard definition:
		// type FooMetadata struct { ... }
		structType = ty
	case *ast.Ident:
		if ty.Obj == nil {
			return nil
		}

		// this might be a type created from another type:
		// type FooMetadata BarMetadata
		// ... but we need to check that the other type definition is a struct type
		typeSpec, ok := ty.Obj.Decl.(*ast.TypeSpec)
		if !ok {
			return nil
		}
		nestedStructType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return nil
		}
		structType = nestedStructType
	}
	return structType
}

func typeNamesUsedInStruct(structType *ast.StructType) []string {
	// recursively find all type names used in the struct type
	var names []string
	for i := range structType.Fields.List {
		// capture names of all of the types (not field names)
		ast.Inspect(structType.Fields.List[i].Type, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}

			// add the type name to the list
			names = append(names, ident.Name)

			// continue inspecting
			return true
		})
	}

	return names
}

func isMetadataTypeCandidate(name string) bool {
	return len(name) > 0 &&
		unicode.IsUpper(rune(name[0])) && // must be exported
		!knownNonMetadataTypeNames.Has(name)
}
