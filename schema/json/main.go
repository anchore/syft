package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/anchore/syft/internal"
	genInt "github.com/anchore/syft/schema/json/internal"
	syftjsonModel "github.com/anchore/syft/syft/formats/syftjson/model"
)

/*
This method of creating the JSON schema only captures strongly typed fields for the purpose of integrations between syft
JSON output and integrations. The downside to this approach is that any values and types used on weakly typed fields
are not captured (empty interfaces). This means that pkg.Package.Metadata is not validated at this time. This approach
can be extended to include specific package metadata struct shapes in the future.
*/

//go:generate go run ./generate/main.go

const schemaVersion = internal.JSONSchemaVersion

func main() {
	write(encode(build()))
}

func build() *jsonschema.Schema {
	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties: true,
		Namer: func(r reflect.Type) string {
			return strings.TrimPrefix(r.Name(), "JSON")
		},
	}
	documentSchema := reflector.ReflectFromType(reflect.TypeOf(&syftjsonModel.Document{}))
	metadataSchema := reflector.ReflectFromType(reflect.TypeOf(&genInt.ArtifactMetadataContainer{}))
	// TODO: inject source definitions

	// inject the definitions of all metadatas into the schema definitions

	var metadataNames []string
	for name, definition := range metadataSchema.Definitions {
		if name == reflect.TypeOf(genInt.ArtifactMetadataContainer{}).Name() {
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
