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

	"github.com/invopop/jsonschema"

	"github.com/anchore/syft/internal"
	syftJsonModel "github.com/anchore/syft/syft/formats/syftjson/model"
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

func assembleTypeContainer(items []any) any {
	structFields := make([]reflect.StructField, len(items))

	for i, item := range items {
		itemType := reflect.TypeOf(item)
		fieldName := itemType.Name()

		structFields[i] = reflect.StructField{
			Name: fieldName,
			Type: itemType,
		}
	}

	structType := reflect.StructOf(structFields)
	return reflect.New(structType).Elem().Interface()
}

func build() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		BaseSchemaID:              schemaID(),
		AllowAdditionalProperties: true,
		Namer: func(r reflect.Type) string {
			return strings.TrimPrefix(r.Name(), "JSON")
		},
	}

	pkgMetadataContainer := assembleTypeContainer(packagemetadata.AllTypes())
	pkgMetadataContainerType := reflect.TypeOf(pkgMetadataContainer)

	// srcMetadataContainer := assembleTypeContainer(sourcemetadata.AllTypes())
	// srcMetadataContainerType := reflect.TypeOf(srcMetadataContainer)

	documentSchema := reflector.ReflectFromType(reflect.TypeOf(&syftJsonModel.Document{}))
	pkgMetadataSchema := reflector.ReflectFromType(reflect.TypeOf(pkgMetadataContainer))
	// srcMetadataSchema := reflector.ReflectFromType(reflect.TypeOf(srcMetadataContainer))

	// TODO: add source metadata types

	// inject the definitions of all packages metadatas into the schema definitions

	var metadataNames []string
	for name, definition := range pkgMetadataSchema.Definitions {
		if name == pkgMetadataContainerType.Name() {
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
	repoRoot, err := packagemetadata.RepoRoot()
	if err != nil {
		fmt.Println("unable to determine repo root")
		os.Exit(1)
	}
	schemaPath := filepath.Join(repoRoot, "schema", "json", fmt.Sprintf("schema-%s.json", internal.JSONSchemaVersion))

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

	_, err = fh.Write(schema)
	if err != nil {
		panic(err)
	}

	defer fh.Close()

	fmt.Printf("Wrote new schema to %q\n", schemaPath)
}
