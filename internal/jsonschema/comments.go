package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/invopop/jsonschema"
)

func copyAliasFieldComments(commentMap map[string]string, repoRoot string) {
	// find all type aliases by parsing Go source files
	aliases := findTypeAliases(repoRoot)

	// for each alias, copy field comments from the source type
	for aliasName, sourceName := range aliases {
		// find all field comments for the source type
		for key, comment := range commentMap {
			// check if this is a field comment for the source type
			// format: "github.com/anchore/syft/syft/pkg.SourceType.FieldName"
			if strings.Contains(key, "."+sourceName+".") {
				// create the corresponding key for the alias
				aliasKey := strings.Replace(key, "."+sourceName+".", "."+aliasName+".", 1)
				commentMap[aliasKey] = comment
			}
		}
	}
}

func findTypeAliases(repoRoot string) map[string]string {
	aliases := make(map[string]string)
	fset := token.NewFileSet()

	// walk through all Go files in the repo
	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// parse the file
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil
		}

		// look for type alias declarations
		ast.Inspect(file, func(n ast.Node) bool {
			typeSpec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}

			// check if this is a type alias (e.g., type A B where B is an identifier)
			ident, ok := typeSpec.Type.(*ast.Ident)
			if !ok {
				return true
			}

			// store the alias mapping: aliasName -> sourceName
			aliases[typeSpec.Name.Name] = ident.Name
			return true
		})

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to find type aliases: %v\n", err)
		panic(err)
	}

	return aliases
}

func hasDescriptionInAlternatives(schema *jsonschema.Schema) bool {
	// check oneOf alternatives
	for _, alt := range schema.OneOf {
		if alt.Description != "" {
			return true
		}
	}
	// check anyOf alternatives
	for _, alt := range schema.AnyOf {
		if alt.Description != "" {
			return true
		}
	}
	return false
}

func warnMissingDescriptions(schema *jsonschema.Schema, metadataNames []string) { //nolint:gocognit
	var missingTypeDescriptions []string
	var missingFieldDescriptions []string

	// check metadata types for missing descriptions
	for _, name := range metadataNames {
		def, ok := schema.Definitions[name]
		if !ok {
			continue
		}

		// check if type has a description
		if def.Description == "" {
			missingTypeDescriptions = append(missingTypeDescriptions, name)
		}

		// check if fields have descriptions
		if def.Properties != nil {
			for _, fieldName := range def.Properties.Keys() {
				fieldSchemaRaw, _ := def.Properties.Get(fieldName)
				fieldSchema, ok := fieldSchemaRaw.(*jsonschema.Schema)
				if !ok {
					continue
				}

				// skip if field has a description
				if fieldSchema.Description != "" {
					continue
				}

				// skip if field is a reference (descriptions come from the referenced type)
				if fieldSchema.Ref != "" {
					continue
				}

				// skip if field is an array/object with items that are references
				if fieldSchema.Items != nil && fieldSchema.Items.Ref != "" {
					continue
				}

				// skip if field uses oneOf/anyOf with descriptions in the alternatives
				if hasDescriptionInAlternatives(fieldSchema) {
					continue
				}

				missingFieldDescriptions = append(missingFieldDescriptions, fmt.Sprintf("%s.%s", name, fieldName))
			}
		}
	}

	// report findings
	if len(missingTypeDescriptions) > 0 {
		fmt.Fprintf(os.Stderr, "\nwarning: %d metadata types are missing descriptions:\n", len(missingTypeDescriptions))
		for _, name := range missingTypeDescriptions {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
	}

	if len(missingFieldDescriptions) > 0 {
		fmt.Fprintf(os.Stderr, "\nwarning: %d fields are missing descriptions:\n", len(missingFieldDescriptions))
		for _, field := range missingFieldDescriptions {
			fmt.Fprintf(os.Stderr, "  - %s\n", field)
		}
	}
}
