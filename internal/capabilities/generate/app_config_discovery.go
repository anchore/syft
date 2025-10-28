package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// AppConfigField represents an application-level configuration field for catalogers
type AppConfigField struct {
	Key          string      // e.g., "golang.search-local-mod-cache-licenses"
	Description  string      // extracted from DescribeFields() method
	DefaultValue interface{} // extracted from Default*() functions
}

// DiscoverAppConfigs discovers all application-level cataloger configuration fields
// from the options package
func DiscoverAppConfigs(repoRoot string) ([]AppConfigField, error) {
	optionsDir := filepath.Join(repoRoot, "cmd", "syft", "internal", "options")

	// parse all .go files in the options directory to extract configuration fields
	configs := []AppConfigField{}

	// define the config files we want to parse with their top-level keys
	configFiles := map[string]string{
		"dotnet.go":       "dotnet",
		"golang.go":       "golang",
		"java.go":         "java",
		"javascript.go":   "javascript",
		"linux_kernel.go": "linux-kernel",
		"nix.go":          "nix",
		"python.go":       "python",
	}

	for filename, topLevelKey := range configFiles {
		filePath := filepath.Join(optionsDir, filename)
		fields, err := extractAppConfigFields(filePath, topLevelKey)
		if err != nil {
			return nil, fmt.Errorf("failed to extract config from %s: %w", filename, err)
		}
		configs = append(configs, fields...)
	}

	// sort by key for consistent output
	sort.Slice(configs, func(i, j int) bool {
		return configs[i].Key < configs[j].Key
	})

	return configs, nil
}

// extractAppConfigFields extracts config fields from an options file
func extractAppConfigFields(filePath, topLevelKey string) ([]AppConfigField, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var configs []AppConfigField

	// find the main config struct (not nested ones)
	configStruct, descriptions := findAppConfigStructAndDescriptions(f, topLevelKey)
	if configStruct == nil {
		return nil, fmt.Errorf("no config struct found in %s", filePath)
	}

	// extract default values from the default function
	defaults := extractAppDefaultValues(f)

	// build config fields from struct fields
	for _, field := range configStruct.Fields.List {
		// extract yaml tag to get the field key
		yamlKey := extractYAMLTag(field)
		if yamlKey == "" || yamlKey == "-" {
			continue
		}

		var fieldName string
		if len(field.Names) > 0 {
			fieldName = field.Names[0].Name
		} else {
			continue
		}

		// build full key path
		fullKey := topLevelKey + "." + yamlKey

		// handle nested structs (e.g., golang.MainModuleVersion)
		if isNestedStruct(field.Type) {
			nestedConfigs := extractNestedAppConfigs(f, fullKey, fieldName, field.Type, descriptions, defaults)
			configs = append(configs, nestedConfigs...)
			continue
		}

		// get description from DescribeFields
		description := descriptions[fieldName]

		// get default value
		defaultValue := defaults[fieldName]

		configs = append(configs, AppConfigField{
			Key:          fullKey,
			Description:  description,
			DefaultValue: defaultValue,
		})
	}

	return configs, nil
}

// findAppConfigStructAndDescriptions finds the main config struct and extracts field descriptions
// from the DescribeFields method
func findAppConfigStructAndDescriptions(f *ast.File, topLevelKey string) (*ast.StructType, map[string]string) {
	expectedName := determineExpectedConfigName(topLevelKey)
	configStruct := findConfigStruct(f, expectedName)
	descriptions := extractDescriptionsFromDescribeFields(f)
	return configStruct, descriptions
}

// determineExpectedConfigName maps the top-level key to the expected config struct name
func determineExpectedConfigName(topLevelKey string) string {
	// handle special cases first
	switch topLevelKey {
	case "linux-kernel":
		return "linuxKernelConfig"
	case "javascript":
		return "javaScriptConfig"
	default:
		return topLevelKey + "Config"
	}
}

// findConfigStruct searches for the config struct with the expected name in the AST
func findConfigStruct(f *ast.File, expectedName string) *ast.StructType {
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			if typeSpec.Name.Name == expectedName {
				return structType
			}
		}
	}
	return nil
}

// extractDescriptionsFromDescribeFields extracts field descriptions from the DescribeFields method
func extractDescriptionsFromDescribeFields(f *ast.File) map[string]string {
	descriptions := make(map[string]string)

	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Name.Name != "DescribeFields" {
			continue
		}

		// extract descriptions from descriptions.Add calls
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			callExpr, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// check if this is a descriptions.Add call
			selector, ok := callExpr.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Add" {
				return true
			}

			// first argument should be a field reference (&o.FieldName or &o.Parent.FieldName)
			if len(callExpr.Args) < 2 {
				return true
			}

			fieldPath := extractFieldPathFromRef(callExpr.Args[0])
			if fieldPath == "" {
				return true
			}

			// second argument is the description string
			description := extractStringLiteral(callExpr.Args[1])
			if description != "" {
				description = cleanDescription(description)
				descriptions[fieldPath] = description
			}

			return true
		})
	}

	return descriptions
}

// extractNestedAppConfigs handles nested config structs like golang.MainModuleVersion
func extractNestedAppConfigs(f *ast.File, parentKey, parentFieldName string, fieldType ast.Expr, descriptions map[string]string, defaults map[string]interface{}) []AppConfigField {
	var configs []AppConfigField

	// find the nested struct type
	var nestedStructName string
	switch t := fieldType.(type) {
	case *ast.Ident:
		nestedStructName = t.Name
	default:
		return nil
	}

	// find the struct definition
	var nestedStruct *ast.StructType
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != nestedStructName {
				continue
			}

			var structOk bool
			nestedStruct, structOk = typeSpec.Type.(*ast.StructType)
			if structOk {
				break
			}
		}
	}

	if nestedStruct == nil {
		return nil
	}

	// extract fields from nested struct
	for _, field := range nestedStruct.Fields.List {
		yamlKey := extractYAMLTag(field)
		if yamlKey == "" || yamlKey == "-" {
			continue
		}

		var fieldName string
		if len(field.Names) > 0 {
			fieldName = field.Names[0].Name
		} else {
			continue
		}

		fullKey := parentKey + "." + yamlKey

		// get description using the nested path (e.g., "MainModuleVersion.FromLDFlags")
		nestedPath := parentFieldName + "." + fieldName
		description := descriptions[nestedPath]

		// try to get default value from nested defaults
		var defaultValue interface{}
		if nestedDefaults, ok := defaults[parentFieldName].(map[string]interface{}); ok {
			defaultValue = nestedDefaults[fieldName]
		}

		configs = append(configs, AppConfigField{
			Key:          fullKey,
			Description:  description,
			DefaultValue: defaultValue,
		})
	}

	return configs
}

// extractAppDefaultValues extracts default values from the default*Config function
func extractAppDefaultValues(f *ast.File) map[string]interface{} {
	defaults := make(map[string]interface{})

	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(funcDecl.Name.Name, "default") {
			continue
		}

		// look for return statements that construct the config struct
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			// look for return statements
			returnStmt, ok := n.(*ast.ReturnStmt)
			if !ok || len(returnStmt.Results) == 0 {
				return true
			}

			// check if returning a struct literal
			compositeLit, ok := returnStmt.Results[0].(*ast.CompositeLit)
			if !ok {
				return true
			}

			// extract field values from the composite literal
			for _, elt := range compositeLit.Elts {
				kvExpr, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}

				// get field name
				ident, ok := kvExpr.Key.(*ast.Ident)
				if !ok {
					continue
				}

				fieldName := ident.Name

				// extract the value
				value := extractAppValue(kvExpr.Value)
				if value != nil {
					defaults[fieldName] = value
				}
			}

			return true
		})
	}

	return defaults
}

// extractAppValue extracts a Go value from an AST expression
func extractAppValue(expr ast.Expr) interface{} {
	switch v := expr.(type) {
	case *ast.BasicLit:
		// string, int, bool literals
		switch v.Kind {
		case token.STRING:
			return strings.Trim(v.Value, `"`)
		case token.INT:
			return v.Value
		case token.FLOAT:
			return v.Value
		}
	case *ast.Ident:
		// boolean values
		if v.Name == "true" {
			return true
		}
		if v.Name == "false" {
			return false
		}
		if v.Name == "nil" {
			return nil
		}
	case *ast.CompositeLit:
		// nested struct literal
		nested := make(map[string]interface{})
		for _, elt := range v.Elts {
			kvExpr, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			ident, ok := kvExpr.Key.(*ast.Ident)
			if !ok {
				continue
			}
			nested[ident.Name] = extractAppValue(kvExpr.Value)
		}
		if len(nested) > 0 {
			return nested
		}
	}
	return nil
}

// extractYAMLTag extracts the yaml tag value from a struct field
func extractYAMLTag(field *ast.Field) string {
	if field.Tag == nil {
		return ""
	}

	tag := strings.Trim(field.Tag.Value, "`")
	tags := reflect.StructTag(tag)
	yamlTag := tags.Get("yaml")

	// handle tags like "field-name,omitempty"
	if idx := strings.Index(yamlTag, ","); idx != -1 {
		yamlTag = yamlTag[:idx]
	}

	return yamlTag
}

// extractFieldPathFromRef extracts field path from & o.FieldName or &o.Parent.FieldName expression
func extractFieldPathFromRef(expr ast.Expr) string {
	unaryExpr, ok := expr.(*ast.UnaryExpr)
	if !ok {
		return ""
	}

	// handle nested field references like &o.MainModuleVersion.FromLDFlags
	var parts []string
	current := unaryExpr.X

	for {
		selectorExpr, ok := current.(*ast.SelectorExpr)
		if !ok {
			break
		}

		// add this selector to the path
		parts = append([]string{selectorExpr.Sel.Name}, parts...)

		// move to the next level
		current = selectorExpr.X
	}

	// join the parts with dots to create the full path
	// e.g., ["MainModuleVersion", "FromLDFlags"] -> "MainModuleVersion.FromLDFlags"
	if len(parts) > 0 {
		return strings.Join(parts, ".")
	}

	return ""
}

// extractStringLiteral extracts a string value from a BasicLit node
func extractStringLiteral(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}

	// remove backticks or quotes
	value := strings.Trim(lit.Value, "`\"")
	return value
}

// cleanDescription cleans up multi-line descriptions
func cleanDescription(desc string) string {
	// replace multiple whitespace with single space
	desc = strings.Join(strings.Fields(desc), " ")
	return strings.TrimSpace(desc)
}

// isNestedStruct checks if a field type is a nested struct (not a pointer or basic type)
func isNestedStruct(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		// check if it's a struct type (not a basic type)
		// basic types would be: string, int, bool, etc.
		basicTypes := map[string]bool{
			"string": true, "int": true, "int8": true, "int16": true, "int32": true, "int64": true,
			"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
			"float32": true, "float64": true, "bool": true, "byte": true, "rune": true,
		}
		return !basicTypes[t.Name]
	case *ast.StarExpr:
		// pointer types are not nested structs for our purposes
		return false
	case *ast.ArrayType, *ast.MapType:
		return false
	default:
		return false
	}
}
