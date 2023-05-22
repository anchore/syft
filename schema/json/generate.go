package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/scylladb/go-set/strset"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/invopop/jsonschema"

	"github.com/anchore/syft/internal"
	syftjsonModel "github.com/anchore/syft/syft/formats/syftjson/model"
	"github.com/anchore/syft/syft/pkg"
)

/*
This method of creating the JSON schema only captures strongly typed fields for the purpose of integrations between syft
JSON output and integrations. The downside to this approach is that any values and types used on weakly typed fields
are not captured (empty interfaces). This means that pkg.Package.Metadata is not validated at this time. This approach
can be extended to include specific package metadata struct shapes in the future.
*/

// This should represent all possible metadatas represented in the pkg.Package.Metadata field (an interface{}).
// When a new package metadata definition is created it will need to be manually added here. The variable name does
// not matter as long as it is exported.

// TODO: this should be generated from reflection of whats in the pkg package
// Should be created during generation below; use reflection's ability to
// create types at runtime.
// should be same name as struct minus metadata
type artifactMetadataContainer struct {
	Alpm               pkg.AlpmMetadata
	Apk                pkg.ApkMetadata
	Binary             pkg.BinaryMetadata
	Cocopods           pkg.CocoapodsMetadata
	Conan              pkg.ConanMetadata
	ConanLock          pkg.ConanLockMetadata
	Dart               pkg.DartPubMetadata
	Dotnet             pkg.DotnetDepsMetadata
	Dpkg               pkg.DpkgMetadata
	Gem                pkg.GemMetadata
	GoBin              pkg.GolangBinMetadata
	GoMod              pkg.GolangModMetadata
	Hackage            pkg.HackageMetadata
	Java               pkg.JavaMetadata
	KbPackage          pkg.KbPackageMetadata
	LinuxKernel        pkg.LinuxKernelMetadata
	LinuxKernelModule  pkg.LinuxKernelModuleMetadata
	Nix                pkg.NixStoreMetadata
	NpmPackage         pkg.NpmPackageJSONMetadata
	NpmPackageLock     pkg.NpmPackageLockJSONMetadata
	MixLock            pkg.MixLockMetadata
	Php                pkg.PhpComposerJSONMetadata
	Portage            pkg.PortageMetadata
	PythonPackage      pkg.PythonPackageMetadata
	PythonPipfilelock  pkg.PythonPipfileLockMetadata
	PythonRequirements pkg.PythonRequirementsMetadata
	RDescriptionFile   pkg.RDescriptionFileMetadata
	Rebar              pkg.RebarLockMetadata
	Rpm                pkg.RpmMetadata
	RustCargo          pkg.CargoPackageMetadata
}

const schemaVersion = internal.JSONSchemaVersion

var metadataExceptions = strset.New(
	"FileMetadata",
)

func main() {
	typeNames := findMetadataDefinitionNames(pkgFiles()...)
	fmt.Println("Discovered metadata types: ", len(typeNames))
	for _, n := range typeNames {
		fmt.Println("  -", n)
	}

	fmt.Println("Crafting new metadata container type...")
	metadata := metadataContainer(typeNames...)
	fmt.Printf("Metadata container: %#v\n", metadata)

	fmt.Printf("Writing json schema for version=%q\n", schemaVersion)
	write(encode(build(metadata)))
}

func pkgFiles() []string {
	values, err := filepath.Glob("../../syft/pkg/*.go")
	if err != nil {
		panic("unable to find package files")
	}
	return values
}

func findMetadataDefinitionNames(paths ...string) []string {
	names := strset.New()
	usedNames := strset.New()
	for _, path := range paths {
		metadataDefinitions, usedTypeNames := findMetadataDefinitionNamesInFile(path)

		// useful for debugging...
		//fmt.Println(path)
		//fmt.Println("Defs:", metadataDefinitions)
		//fmt.Println("Used Types:", usedTypeNames)
		//fmt.Println()

		names.Add(metadataDefinitions...)
		usedNames.Add(usedTypeNames...)
	}

	// any definition that is used within another struct should not be considered a top-level metadata definition
	names.Remove(usedNames.List()...)

	strNames := names.List()
	sort.Strings(strNames)

	// note: 30 is a point-in-time gut check. This number could be updated if new metadata definitions are added, but is not required.
	// it is really intended to catch any major issues with the generation process that would generate, say, 0 definitions.
	if len(strNames) < 30 {
		panic("not enough metadata definitions found (discovered: " + fmt.Sprintf("%d", len(strNames)) + ")")
	}

	return strNames
}

func findMetadataDefinitionNamesInFile(path string) ([]string, []string) {
	// set up the parser
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, path, nil, parser.ParseComments)
	if err != nil {
		panic(err)
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

			structType, ok := spec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			// check if the struct type ends with "Metadata"
			name := spec.Name.String()

			// only look for exported types that end with "Metadata"
			if isMetadataTypeCandidate(name) {
				// print the full declaration of the struct type
				metadataDefinitions = append(metadataDefinitions, name)
				usedTypeNames = append(usedTypeNames, typeNamesUsedInStruct(structType)...)
			}
		}
	}
	return metadataDefinitions, usedTypeNames
}

func typeNamesUsedInStruct(structType *ast.StructType) []string {
	// recursively find all type names used in the struct type
	var names []string
	for i, _ := range structType.Fields.List {
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
		strings.HasSuffix(name, "Metadata") &&
		unicode.IsUpper(rune(name[0])) && // must be exported
		!metadataExceptions.Has(name)
}

func metadataContainer(names ...string) any {
	pkgPkg := getPackage("github.com/anchore/syft/syft/pkg")

	var structFields []reflect.StructField
	for _, typeName := range names {
		fieldName := typeName
		fieldType := pkgPkg.Scope().Lookup(typeName).Type()
		newField := reflect.StructField{
			Name: fieldName,
			Type: reflect.PtrTo(reflect.TypeOf(fieldType)),
		}
		structFields = append(structFields, newField)

	}

	structType := reflect.StructOf(structFields)
	instance := reflect.New(structType)

	return instance
}

func getPackage(importPath string) *types.Package {
	p, err := importer.Default().Import(importPath)
	if err != nil {
		panic(err)
	}
	return p
}

func build(metadataContainer any) *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties: true,
		Namer: func(r reflect.Type) string {
			return strings.TrimPrefix(r.Name(), "JSON")
		},
	}
	documentSchema := reflector.ReflectFromType(reflect.TypeOf(&syftjsonModel.Document{}))
	metadataSchema := reflector.ReflectFromType(reflect.TypeOf(&metadataContainer))
	// TODO: inject source definitions

	// inject the definitions of all metadatas into the schema definitions

	var metadataNames []string
	for name, definition := range metadataSchema.Definitions {
		if name == "artifactMetadataContainer" {
			// ignore the definition for the fake container
			continue
		}
		documentSchema.Definitions[name] = definition
		if strings.HasSuffix(name, "Metadata") {
			metadataNames = append(metadataNames, name)
		}
	}

	// ensure the generated list of names is stable between runs
	sort.Strings(metadataNames)

	var metadataTypes = []map[string]string{
		// allow for no metadata to be provided
		{"type": "null"},
	}
	for _, name := range metadataNames {
		metadataTypes = append(metadataTypes, map[string]string{
			"$ref": fmt.Sprintf("#/$defs/%s", name),
		})
	}

	// set the "anyOf" field for Package.Metadata to be a conjunction of several types
	documentSchema.Definitions["Package"].Properties.Set("metadata", map[string][]map[string]string{
		"anyOf": metadataTypes,
	})

	return documentSchema
}

func encode(schema *jsonschema.Schema) []byte {
	var newSchemaBuffer = new(bytes.Buffer)
	enc := json.NewEncoder(newSchemaBuffer)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(&schema)
	if err != nil {
		panic(err)
	}

	return newSchemaBuffer.Bytes()
}

func write(schema []byte) {
	filename := fmt.Sprintf("schema-%s.json", schemaVersion)

	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		// check if the schema is the same...
		existingFh, err := os.Open(filename)
		if err != nil {
			panic(err)
		}

		existingSchemaBytes, err := io.ReadAll(existingFh)
		if err != nil {
			panic(err)
		}

		if bytes.Equal(existingSchemaBytes, schema) {
			// the generated schema is the same, bail with no error :)
			fmt.Println("No change to the existing schema!")
			os.Exit(0)
		}

		// the generated schema is different, bail with error :(
		fmt.Printf("Cowardly refusing to overwrite existing schema (%s)!\nSee the schema/json/README.md for how to increment\n", filename)
		os.Exit(1)
	}

	fh, err := os.Create(filename)
	if err != nil {
		panic(err)
	}

	_, err = fh.Write(schema)
	if err != nil {
		panic(err)
	}

	defer fh.Close()

	fmt.Printf("Wrote new schema to %q\n", filename)
}
