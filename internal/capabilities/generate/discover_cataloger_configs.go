// this file discovers cataloger configuration structs using AST parsing to find Config structs and extract fields with app-config annotations.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/capabilities/internal"
)

// ConfigField represents a single field in a configuration struct
type ConfigField struct {
	Name        string // e.g., "SearchLocalModCacheLicenses"
	Type        string // e.g., "bool", "string", "[]string", etc.
	Description string // extracted from doc comment (1-2 sentences)
	AppKey      string // from "// app-config: golang.search-local-mod-cache-licenses"
}

// ConfigInfo represents a discovered configuration struct
type ConfigInfo struct {
	PackageName string        // e.g., "golang", "python", "dotnet"
	StructName  string        // e.g., "CatalogerConfig", "MainModuleVersionConfig"
	Fields      []ConfigField // all fields with their metadata
}

var appConfigAnnotationPattern = regexp.MustCompile(`^//\s*app-config:\s*(.+)$`)

// DiscoverConfigs walks the cataloger directory and discovers all configuration structs
// Returns map where key is "packageName.StructName" (e.g., "golang.CatalogerConfig")
func DiscoverConfigs(repoRoot string) (map[string]ConfigInfo, error) {
	catalogerRoot := filepath.Join(repoRoot, "syft", "pkg", "cataloger")
	return DiscoverConfigsFromPath(catalogerRoot)
}

// DiscoverConfigsFromPath walks the given directory and discovers all configuration structs
// Returns map where key is "packageName.StructName" (e.g., "golang.CatalogerConfig")
func DiscoverConfigsFromPath(catalogerRoot string) (map[string]ConfigInfo, error) {
	// find all .go files under the directory recursively
	var files []string
	err := filepath.Walk(catalogerRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk cataloger directory: %w", err)
	}

	discovered := make(map[string]ConfigInfo)

	for _, file := range files {
		configs, err := discoverConfigsInFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}

		for key, config := range configs {
			if _, ok := discovered[key]; ok {
				return nil, fmt.Errorf("duplicate config struct %q found in %s", key, file)
			}
			discovered[key] = config
		}
	}

	return discovered, nil
}

func discoverConfigsInFile(path string) (map[string]ConfigInfo, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	// extract package name from file path (use absolute path, not relative)
	packageName := extractPackageNameFromPath(path)
	if packageName == "" {
		return nil, nil
	}

	discovered := make(map[string]ConfigInfo)

	// find all type declarations
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

			// check if this is a struct type that looks like a config
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			// filter for config-related struct names
			structName := typeSpec.Name.Name
			if !isConfigStruct(structName) {
				continue
			}

			// extract fields from the struct
			fields := extractCatalogerConfigFields(structType)
			if len(fields) == 0 {
				// skip structs with no documented config fields
				continue
			}

			config := ConfigInfo{
				PackageName: packageName,
				StructName:  structName,
				Fields:      fields,
			}

			key := packageName + "." + structName
			discovered[key] = config
		}
	}

	return discovered, nil
}

// isConfigStruct determines if a struct name looks like a configuration struct
func isConfigStruct(name string) bool {
	// check for common config patterns
	return strings.Contains(name, "Config")
}

// extractCatalogerConfigFields parses struct fields and extracts their metadata
func extractCatalogerConfigFields(structType *ast.StructType) []ConfigField {
	return extractCatalogerConfigFieldsRecursive(structType, make(map[string]bool), false)
}

// extractCatalogerConfigFieldsRecursive parses struct fields and extracts their metadata,
// handling embedded structs recursively with cycle detection.
// requireAppConfig controls whether to require app-config annotations:
//   - false for top-level struct (only include fields with app-config)
//   - true for embedded structs (include all exported fields)
func extractCatalogerConfigFieldsRecursive(structType *ast.StructType, visitedTypes map[string]bool, fromEmbedded bool) []ConfigField {
	var fields []ConfigField

	for _, field := range structType.Fields.List {
		// handle embedded fields with no names
		if len(field.Names) == 0 {
			// this is an embedded field - resolve and extract its fields
			embeddedFields := resolveEmbeddedStructFields(field.Type, visitedTypes)
			fields = append(fields, embeddedFields...)
			continue
		}

		// extract field name
		fieldName := field.Names[0].Name

		// skip unexported fields
		if !ast.IsExported(fieldName) {
			continue
		}

		// extract field type as string
		fieldType := formatFieldType(field.Type)

		// extract doc comment and app-config annotation
		description, appKey := extractFieldComments(field.Doc)

		// for top-level fields, only include fields that have an app-config annotation
		// for embedded struct fields, include all exported fields
		if !fromEmbedded && appKey == "" {
			continue
		}

		fields = append(fields, ConfigField{
			Name:        fieldName,
			Type:        fieldType,
			Description: description,
			AppKey:      appKey,
		})
	}

	return fields
}

// resolveEmbeddedStructFields resolves an embedded struct type and extracts its fields recursively
func resolveEmbeddedStructFields(fieldType ast.Expr, visitedTypes map[string]bool) []ConfigField {
	// extract the type name from the expression
	typeName := formatFieldType(fieldType)

	// check for cycles
	if visitedTypes[typeName] {
		return nil // avoid infinite recursion
	}
	visitedTypes[typeName] = true

	// parse the type to get package and struct name
	// e.g., "cataloging.ArchiveSearchConfig" -> package="cataloging", struct="ArchiveSearchConfig"
	var packageName, structName string
	if strings.Contains(typeName, ".") {
		parts := strings.Split(typeName, ".")
		if len(parts) == 2 {
			packageName = parts[0]
			structName = parts[1]
		}
	} else {
		// embedded type in the same package - would need same-file resolution
		// for now, we'll skip these as they're less common
		return nil
	}

	if packageName == "" || structName == "" {
		return nil
	}

	// find the file containing this struct
	// we need to search in the syft codebase for this package
	repoRoot, err := internal.RepoRoot()
	if err != nil {
		return nil
	}

	// try common locations for the package
	searchPaths := []string{
		filepath.Join(repoRoot, "syft", packageName),
		filepath.Join(repoRoot, "syft", "pkg", packageName),
		filepath.Join(repoRoot, "syft", "cataloging", packageName),
	}

	// add the direct path if packageName is a subpackage indicator
	if strings.Contains(packageName, "/") || !strings.Contains(packageName, ".") {
		searchPaths = append(searchPaths, filepath.Join(repoRoot, "syft", packageName))
	}

	for _, searchPath := range searchPaths {
		// try to find a .go file in this directory that contains the struct
		matches, err := filepath.Glob(filepath.Join(searchPath, "*.go"))
		if err != nil {
			continue
		}

		for _, file := range matches {
			// skip test files
			if strings.HasSuffix(file, "_test.go") {
				continue
			}

			// parse the file and look for the struct
			structType := findStructInFile(file, structName)
			if structType != nil {
				// found it! recursively extract fields (fromEmbedded=true means include all exported fields)
				return extractCatalogerConfigFieldsRecursive(structType, visitedTypes, true)
			}
		}
	}

	return nil
}

// findStructInFile parses a Go file and returns the struct type with the given name, or nil if not found
func findStructInFile(filePath, structName string) *ast.StructType {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil
	}

	// find the struct declaration
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

			if typeSpec.Name.Name == structName {
				structType, ok := typeSpec.Type.(*ast.StructType)
				if ok {
					return structType
				}
			}
		}
	}

	return nil
}

// extractFieldComments parses field comments to extract description and app-config annotation
func extractFieldComments(commentGroup *ast.CommentGroup) (description string, appKey string) {
	if commentGroup == nil {
		return "", ""
	}

	var descLines []string

	for _, comment := range commentGroup.List {
		text := strings.TrimPrefix(comment.Text, "//")
		text = strings.TrimSpace(text)

		// check if this is an app-config annotation
		if matches := appConfigAnnotationPattern.FindStringSubmatch(comment.Text); len(matches) > 1 {
			appKey = strings.TrimSpace(matches[1])
			continue
		}

		// accumulate description lines
		if text != "" {
			descLines = append(descLines, text)
		}
	}

	// join description lines
	if len(descLines) > 0 {
		description = strings.Join(descLines, " ")
	}

	return description, appKey
}

// formatFieldType converts an ast.Expr type to a readable string representation
func formatFieldType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		// handle package.Type (e.g., cataloging.ArchiveSearchConfig)
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.ArrayType:
		// handle []Type
		return "[]" + formatFieldType(t.Elt)
	case *ast.MapType:
		// handle map[K]V
		return "map[" + formatFieldType(t.Key) + "]" + formatFieldType(t.Value)
	case *ast.StarExpr:
		// handle *Type
		return "*" + formatFieldType(t.X)
	case *ast.InterfaceType:
		return "interface{}"
	default:
		// fallback for complex types
		return fmt.Sprintf("%T", expr)
	}
}

// DiscoverAllowedConfigStructs parses the pkgcataloging.Config struct and returns
// a set of allowed config struct names (e.g., "golang.CatalogerConfig").
// This is used to filter discovered configs to only include top-level cataloger configs
// that are actually referenced in the main Config struct.
func DiscoverAllowedConfigStructs(repoRoot string) (map[string]bool, error) {
	configFilePath := filepath.Join(repoRoot, "syft", "cataloging", "pkgcataloging", "config.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, configFilePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	allowedConfigs := make(map[string]bool)

	// find the Config struct declaration
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

			// we're looking for the "Config" struct specifically
			if typeSpec.Name.Name != "Config" {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			// extract field types from the Config struct
			for _, field := range structType.Fields.List {
				// skip embedded fields with no names
				if len(field.Names) == 0 {
					continue
				}

				// extract field type as "package.StructName"
				fieldType := formatFieldType(field.Type)

				// only include types that look like config structs (contain a dot for package.Type)
				if strings.Contains(fieldType, ".") {
					allowedConfigs[fieldType] = true
				}
			}

			// we found the Config struct, no need to continue
			return allowedConfigs, nil
		}
	}

	return nil, fmt.Errorf("config struct not found in %s", configFilePath)
}
