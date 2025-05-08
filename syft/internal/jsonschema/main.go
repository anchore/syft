package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/invopop/jsonschema"

	"github.com/anchore/syft/internal"
	syftJsonModel "github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/internal/packagemetadata"
)

/*
This method of creating the JSON schema only captures strongly typed fields for the purpose of integrations between syft
JSON output and integrations. The downside to this approach is that any values and types used on weakly typed fields
are not captured (empty interfaces). This means that pkg.Package.Metadata is not validated at this time. This approach
can be extended to include specific package metadata struct shapes in the future.
*/

func main() {
	write(encode(build()))
}

func schemaID() jsonschema.ID {
	// Today we do not host the schemas at this address, but per the JSON schema spec we should be referencing
	// the schema by a URL in a domain we control. This is a placeholder for now.
	return jsonschema.ID(fmt.Sprintf("anchore.io/schema/syft/json/%s", internal.JSONSchemaVersion))
}

func assembleTypeContainer(items []any) (any, map[string]string) {
	structFields := make([]reflect.StructField, len(items))
	mapping := make(map[string]string, len(items))
	typesMissingNames := make([]reflect.Type, 0)
	for i, item := range items {
		itemType := reflect.TypeOf(item)

		jsonName := packagemetadata.JSONName(item)
		fieldName := strcase.ToCamel(jsonName)

		if jsonName == "" {
			typesMissingNames = append(typesMissingNames, itemType)
			continue
		}

		mapping[itemType.Name()] = fieldName

		structFields[i] = reflect.StructField{
			Name: fieldName,
			Type: itemType,
		}
	}

	if len(typesMissingNames) > 0 {
		fmt.Println("the following types are missing JSON names (manually curated in ./syft/internal/packagemetadata/names.go):")
		for _, t := range typesMissingNames {
			fmt.Println("  - ", t.Name())
		}
		os.Exit(1)
	}

	structType := reflect.StructOf(structFields)
	return reflect.New(structType).Elem().Interface(), mapping
}

func build() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		BaseSchemaID:              schemaID(),
		AllowAdditionalProperties: true,
		Namer: func(r reflect.Type) string {
			return strings.TrimPrefix(r.Name(), "JSON")
		},
	}

	pkgMetadataContainer, pkgMetadataMapping := assembleTypeContainer(packagemetadata.AllTypes())
	pkgMetadataContainerType := reflect.TypeOf(pkgMetadataContainer)

	// srcMetadataContainer := assembleTypeContainer(sourcemetadata.AllTypes())
	// srcMetadataContainerType := reflect.TypeOf(srcMetadataContainer)

	documentSchema := reflector.ReflectFromType(reflect.TypeOf(&syftJsonModel.Document{}))
	pkgMetadataSchema := reflector.ReflectFromType(reflect.TypeOf(pkgMetadataContainer))
	// srcMetadataSchema := reflector.ReflectFromType(reflect.TypeOf(srcMetadataContainer))

	// TODO: add source metadata types

	// inject the definitions of all packages metadata into the schema definitions

	var metadataNames []string
	for typeName, definition := range pkgMetadataSchema.Definitions {
		if typeName == pkgMetadataContainerType.Name() {
			// ignore the definition for the fake container
			continue
		}

		displayName, ok := pkgMetadataMapping[typeName]
		if ok {
			// this is a package metadata type...
			documentSchema.Definitions[displayName] = definition
			metadataNames = append(metadataNames, displayName)
		} else {
			// this is a type that the metadata type uses (e.g. DpkgFileRecord)
			documentSchema.Definitions[typeName] = definition
		}
	}

	// ensure the generated list of names is stable between runs
	sort.Strings(metadataNames)

	metadataTypes := []map[string]string{
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
	newSchemaBuffer := new(bytes.Buffer)
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
	repoRoot, err := packagemetadata.RepoRoot()
	if err != nil {
		fmt.Println("unable to determine repo root")
		os.Exit(1)
	}
	schemaPath := filepath.Join(repoRoot, "schema", "json", fmt.Sprintf("schema-%s.json", internal.JSONSchemaVersion))
	latestSchemaPath := filepath.Join(repoRoot, "schema", "json", "schema-latest.json")

	if _, err := os.Stat(schemaPath); !os.IsNotExist(err) {
		// check if the schema is the same...
		existingFh, err := os.Open(schemaPath)
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
		fmt.Printf("Cowardly refusing to overwrite existing schema (%s)!\nSee the schema/json/README.md for how to increment\n", schemaPath)
		os.Exit(1)
	}

	fh, err := os.Create(schemaPath)
	if err != nil {
		panic(err)
	}
	defer fh.Close()

	_, err = fh.Write(schema)
	if err != nil {
		panic(err)
	}

	latestFile, err := os.Create(latestSchemaPath)
	if err != nil {
		panic(err)
	}
	defer latestFile.Close()

	_, err = latestFile.Write(schema)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Wrote new schema to %q\n", schemaPath)
}
