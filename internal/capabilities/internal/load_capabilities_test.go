// this file verifies the claims made in cataloger/*/capabilities.yaml against test observations and source code, ensuring cataloger capabilities are accurate and complete.
package internal

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/pkg"
	_ "github.com/anchore/syft/syft/pkg/cataloger"
)

// requireParserObservations controls whether TestAllCatalogersHaveObservations enforces that all parsers have observations
// - true: fail test if any parser is missing observations (strict mode)
// - false: only check custom catalogers, skip parser checks (lenient mode, not all parsers are observable)
const requireParserObservations = false

// metadataTypeCoverageExceptions lists metadata types that are allowed to not be represented in any cataloger
var metadataTypeCoverageExceptions = strset.New(
	reflect.TypeOf(pkg.MicrosoftKbPatch{}).Name(),
)

// packageTypeCoverageExceptions lists package types that are allowed to not be represented in any cataloger
var packageTypeCoverageExceptions = strset.New(
	string(pkg.JenkinsPluginPkg), // TODO: this should probably be covered by a cataloger test one day
	string(pkg.KbPkg),
)

// observationExceptions maps cataloger/parser names to observation types that should be ignored during validation
//
// TestAllCatalogersHaveObservations:
//   - always checks custom catalogers
//   - checks parsers only if requireParserObservations=true
//   - nil or non-nil value: skip existence check for this cataloger/parser
//
// examples:
//
//	"graalvm-native-image-cataloger": nil,  // custom cataloger: skip existence check
//	"linux-kernel-cataloger": strset.New("relationships"),  // custom cataloger: skip only relationships validation
//	"conan-cataloger/parseConanLock": nil,  // parser: skip all observation validation
//	"cataloger-name/parser-function": strset.New("file_digests"),  // parser: skip only file_digests validation
var observationExceptions = map[string]*strset.Set{
	// for the graalvm-native-image-cataloger, we don't have a really reliable test fixture yet
	"graalvm-native-image-cataloger": nil,
	// the linux-kernel-cataloger produces relationships but aren't really indicative of dependency information in the way the user might expect
	"linux-kernel-cataloger": strset.New("relationships"),
}

func TestLoadDocument(t *testing.T) {
	doc, err := capabilities.LoadDocument()
	require.NoError(t, err)
	require.NotNil(t, doc)

	// validate application config is loaded
	assert.NotEmpty(t, doc.ApplicationConfig, "should have application config")

	// validate catalogers are loaded and merged from all cataloger/*/capabilities.yaml files
	assert.NotEmpty(t, doc.Catalogers, "should have catalogers")
	assert.Greater(t, len(doc.Catalogers), 50, "should have at least 50 catalogers")

	// validate configs are loaded
	assert.NotEmpty(t, doc.Configs, "should have configs")

	// check that catalogers are sorted by name
	for i := 1; i < len(doc.Catalogers); i++ {
		assert.LessOrEqual(t, doc.Catalogers[i-1].Name, doc.Catalogers[i].Name,
			"catalogers should be sorted by name")
	}
}

func TestPackages(t *testing.T) {
	catalogers, err := capabilities.Packages()
	require.NoError(t, err)
	require.NotNil(t, catalogers)

	assert.Greater(t, len(catalogers), 50, "should have at least 50 catalogers")
}

// TestConfigCompleteness validates the integrity of config references in cataloger/*/capabilities.yaml, ensuring that all
// configs in the configs section are referenced by at least one cataloger, all cataloger config references exist,
// and all app-key references in config fields exist in the application section.
func TestConfigCompleteness(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the cataloger/*/capabilities.yaml files
	doc, _, err := LoadCapabilities(CatalogerDir(repoRoot), repoRoot)
	require.NoError(t, err)

	// collect all validation errors before failing
	var errors []string

	// validation 1: all entries in configs section are referenced by at least one cataloger
	configsReferenced := make(map[string]bool)
	for _, cataloger := range doc.Catalogers {
		if cataloger.Config != "" {
			configsReferenced[cataloger.Config] = true
		}
	}

	for configKey := range doc.Configs {
		if !configsReferenced[configKey] {
			errors = append(errors, fmt.Sprintf("Config %q is not referenced by any cataloger", configKey))
		}
	}

	// validation 2: all catalogers with non-empty config field have entry in configs
	for _, cataloger := range doc.Catalogers {
		if cataloger.Config != "" {
			if _, exists := doc.Configs[cataloger.Config]; !exists {
				errors = append(errors, fmt.Sprintf("Cataloger %q references config %q which doesn't exist in configs section", cataloger.Name, cataloger.Config))
			}
		}
	}

	// validation 3: all app-key references in configs exist in app-config section
	// build a set of all app-config keys for quick lookup
	appConfigKeys := make(map[string]bool)
	for _, appConfig := range doc.ApplicationConfig {
		appConfigKeys[appConfig.Key] = true
	}

	for configName, configEntry := range doc.Configs {
		for _, field := range configEntry.Fields {
			if field.AppKey != "" {
				if !appConfigKeys[field.AppKey] {
					errors = append(errors, fmt.Sprintf("Config field %q.%s references app-key %q which doesn't exist in app-config section", configName, field.Key, field.AppKey))
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Config completeness validation failed", strings.Join(errors, "\n"))
	}
}

// TestCapabilityConfigFieldReferences validates that config field names referenced in capability conditions
// actually exist in the cataloger's config struct, preventing typos and ensuring capability conditions can
// be properly evaluated at runtime.
func TestCapabilityConfigFieldReferences(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := LoadCapabilities(CatalogerDir(repoRoot), repoRoot)
	require.NoError(t, err)

	// collect all validation errors before failing
	var errors []string

	// for each cataloger with CapabilitiesV2
	for _, cataloger := range doc.Catalogers {
		// check cataloger-level CapabilitiesV2 (for custom catalogers)
		if cataloger.Type == "custom" && len(cataloger.Capabilities) > 0 {
			// load the cataloger's config struct if it has one
			if cataloger.Config != "" {
				configEntry, exists := doc.Configs[cataloger.Config]
				if !exists {
					errors = append(errors, fmt.Sprintf("Cataloger %q references config %q which doesn't exist", cataloger.Name, cataloger.Config))
					continue
				}

				// build a set of valid config field names
				validFields := make(map[string]bool)
				for _, field := range configEntry.Fields {
					validFields[field.Key] = true
				}

				// validate each capability field
				for _, capField := range cataloger.Capabilities {
					// check conditions for config field references
					for _, condition := range capField.Conditions {
						for fieldName := range condition.When {
							if !validFields[fieldName] {
								errors = append(errors,
									fmt.Sprintf("Cataloger %q capability field %q references config field %q which doesn't exist in config struct %q",
										cataloger.Name, capField.Name, fieldName, cataloger.Config))
							}
						}
					}
				}
			} else if len(cataloger.Capabilities) > 0 {
				// cataloger has CapabilitiesV2 with conditions but no config - check if any conditions reference fields
				for _, capField := range cataloger.Capabilities {
					if len(capField.Conditions) > 0 {
						for _, condition := range capField.Conditions {
							if len(condition.When) > 0 {
								errors = append(errors,
									fmt.Sprintf("Cataloger %q capability field %q has conditions but cataloger has no config struct",
										cataloger.Name, capField.Name))
								break
							}
						}
					}
				}
			}
		}

		// check parser-level CapabilitiesV2 (for generic catalogers)
		if cataloger.Type == "generic" {
			for _, p := range cataloger.Parsers {
				if len(p.Capabilities) > 0 {
					// load the cataloger's config struct if it has one
					if cataloger.Config != "" {
						configEntry, exists := doc.Configs[cataloger.Config]
						if !exists {
							errors = append(errors, fmt.Sprintf("Cataloger %q references config %q which doesn't exist", cataloger.Name, cataloger.Config))
							continue
						}

						// build a set of valid config field names
						validFields := make(map[string]bool)
						for _, field := range configEntry.Fields {
							validFields[field.Key] = true
						}

						// validate each capability field
						for _, capField := range p.Capabilities {
							// check conditions for config field references
							for _, condition := range capField.Conditions {
								for fieldName := range condition.When {
									if !validFields[fieldName] {
										errors = append(errors,
											fmt.Sprintf("Parser %q/%s capability field %q references config field %q which doesn't exist in config struct %q",
												cataloger.Name, p.ParserFunction, capField.Name, fieldName, cataloger.Config))
									}
								}
							}
						}
					} else {
						// parser has CapabilitiesV2 with conditions but cataloger has no config
						for _, capField := range p.Capabilities {
							if len(capField.Conditions) > 0 {
								for _, condition := range capField.Conditions {
									if len(condition.When) > 0 {
										errors = append(errors,
											fmt.Sprintf("Parser %q/%s capability field %q has conditions but cataloger has no config struct",
												cataloger.Name, p.ParserFunction, capField.Name))
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "CapabilityV2 config field reference validation failed", strings.Join(errors, "\n"))
	}
}

// TestCapabilityFieldNaming validates that all capability field names follow known patterns
// (e.g., "license", "dependency.depth", "package_manager.files.listing"), catching typos and ensuring
// consistency across catalogers.
func TestCapabilityFieldNaming(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := LoadCapabilities(CatalogerDir(repoRoot), repoRoot)
	require.NoError(t, err)

	// define known capability field paths
	knownFields := strset.New(
		"license",
		"dependency.depth",
		"dependency.edges",
		"dependency.kinds",
		"package_manager.files.listing",
		"package_manager.files.digests",
		"package_manager.package_integrity_hash",
	)

	// collect all validation errors/warnings
	var errors []string

	// check cataloger-level CapabilitiesV2
	for _, cataloger := range doc.Catalogers {
		if cataloger.Type == "custom" && len(cataloger.Capabilities) > 0 {
			for _, capField := range cataloger.Capabilities {
				if !knownFields.Has(capField.Name) {
					errors = append(errors,
						fmt.Sprintf("Cataloger %q uses unknown capability field %q - may be a typo or new field not in known list",
							cataloger.Name, capField.Name))
				}
			}
		}

		// check parser-level CapabilitiesV2
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				if len(parser.Capabilities) > 0 {
					for _, capField := range parser.Capabilities {
						if !knownFields.Has(capField.Name) {
							errors = append(errors,
								fmt.Sprintf("Parser %q/%s uses unknown capability field %q - may be a typo or new field not in known list",
									cataloger.Name, parser.ParserFunction, capField.Name))
						}
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Capability field naming validation failed", strings.Join(errors, "\n"))
	}
}

// TestCapabilityValueTypes validates that capability field values match their expected types based on the
// field name (e.g., boolean fields like "license" must have bool values, array fields like "dependency.depth"
// must have []string values), preventing type mismatches that would cause runtime errors.
func TestCapabilityValueTypes(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := LoadCapabilities(CatalogerDir(repoRoot), repoRoot)
	require.NoError(t, err)

	// collect all validation errors
	var errors []string

	// validate cataloger-level CapabilitiesV2
	for _, cataloger := range doc.Catalogers {
		if cataloger.Type == "custom" && len(cataloger.Capabilities) > 0 {
			for _, capField := range cataloger.Capabilities {
				// validate default value type
				err := validateCapabilityValueType(capField.Name, capField.Default)
				if err != nil {
					errors = append(errors,
						fmt.Sprintf("Cataloger %q capability field %q default value: %v",
							cataloger.Name, capField.Name, err))
				}

				// validate condition value types
				for i, condition := range capField.Conditions {
					err := validateCapabilityValueType(capField.Name, condition.Value)
					if err != nil {
						errors = append(errors,
							fmt.Sprintf("Cataloger %q capability field %q condition %d value: %v",
								cataloger.Name, capField.Name, i, err))
					}
				}
			}
		}

		// validate parser-level CapabilitiesV2
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				if len(parser.Capabilities) > 0 {
					for _, capField := range parser.Capabilities {
						// validate default value type
						err := validateCapabilityValueType(capField.Name, capField.Default)
						if err != nil {
							errors = append(errors,
								fmt.Sprintf("Parser %q/%s capability field %q default value: %v",
									cataloger.Name, parser.ParserFunction, capField.Name, err))
						}

						// validate condition value types
						for i, condition := range capField.Conditions {
							err := validateCapabilityValueType(capField.Name, condition.Value)
							if err != nil {
								errors = append(errors,
									fmt.Sprintf("Parser %q/%s capability field %q condition %d value: %v",
										cataloger.Name, parser.ParserFunction, capField.Name, i, err))
							}
						}
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Capability value type validation failed", strings.Join(errors, "\n"))
	}
}

// validateCapabilityValueType checks if a value matches the expected type for a capability field
func validateCapabilityValueType(fieldPath string, value interface{}) error {
	if value == nil {
		return nil // nil is acceptable
	}

	switch fieldPath {
	case "license",
		"package_manager.files.listing",
		"package_manager.files.digests",
		"package_manager.package_integrity_hash":
		// expect bool
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected bool, got %T", value)
		}

	case "dependency.depth", "dependency.kinds":
		// expect []string or []interface{} that can be converted to []string
		switch v := value.(type) {
		case []string:
			// ok
		case []interface{}:
			// check each element is a string
			for i, elem := range v {
				if _, ok := elem.(string); !ok {
					return fmt.Errorf("expected []string, but element %d is %T", i, elem)
				}
			}
		default:
			return fmt.Errorf("expected []string, got %T", value)
		}

	case "dependency.edges":
		// expect string
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string, got %T", value)
		}

	default:
		// unknown field, skip validation
		return nil
	}

	return nil
}

// TestMetadataTypesHaveJSONSchemaTypes validates that metadata_types and json_schema_types arrays are synchronized
// in packages.yaml, ensuring every metadata type (e.g., "pkg.AlpmDBEntry") has a corresponding json_schema_type
// (e.g., "AlpmDbEntry") with correct conversion, which is required for JSON schema generation.
func TestMetadataTypesHaveJSONSchemaTypes(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := LoadCapabilities(CatalogerDir(repoRoot), repoRoot)
	require.NoError(t, err)

	// collect all validation errors
	var errors []string

	// validate cataloger-level types (custom catalogers)
	for _, c := range doc.Catalogers {
		if c.Type == "custom" {
			if len(c.MetadataTypes) > 0 {
				// verify counts match
				if len(c.MetadataTypes) != len(c.JSONSchemaTypes) {
					errors = append(errors,
						fmt.Sprintf("Cataloger %q has %d metadata_types but %d json_schema_types (counts must match)",
							c.Name, len(c.MetadataTypes), len(c.JSONSchemaTypes)))
					continue
				}

				// verify each metadata_type converts to its corresponding json_schema_type
				for i, metadataType := range c.MetadataTypes {
					expectedJSONSchemaType := convertMetadataTypeToJSONSchemaType(metadataType)
					if expectedJSONSchemaType == "" {
						errors = append(errors,
							fmt.Sprintf("Cataloger %q metadata_type[%d] %q could not be converted to json_schema_type (not found in packagemetadata registry)",
								c.Name, i, metadataType))
						continue
					}

					actualJSONSchemaType := c.JSONSchemaTypes[i]
					if expectedJSONSchemaType != actualJSONSchemaType {
						errors = append(errors,
							fmt.Sprintf("Cataloger %q metadata_type[%d] %q should convert to json_schema_type %q but found %q",
								c.Name, i, metadataType, expectedJSONSchemaType, actualJSONSchemaType))
					}
				}
			}
		}

		// validate parser-level types (generic catalogers)
		if c.Type == "generic" {
			for _, p := range c.Parsers {
				if len(p.MetadataTypes) > 0 {
					// verify counts match
					if len(p.MetadataTypes) != len(p.JSONSchemaTypes) {
						errors = append(errors,
							fmt.Sprintf("Parser %q/%s has %d metadata_types but %d json_schema_types (counts must match)",
								c.Name, p.ParserFunction, len(p.MetadataTypes), len(p.JSONSchemaTypes)))
						continue
					}

					// verify each metadata_type converts to its corresponding json_schema_type
					for i, metadataType := range p.MetadataTypes {
						expectedJSONSchemaType := convertMetadataTypeToJSONSchemaType(metadataType)
						if expectedJSONSchemaType == "" {
							errors = append(errors,
								fmt.Sprintf("Parser %q/%s metadata_type[%d] %q could not be converted to json_schema_type (not found in packagemetadata registry)",
									c.Name, p.ParserFunction, i, metadataType))
							continue
						}

						actualJSONSchemaType := p.JSONSchemaTypes[i]
						if expectedJSONSchemaType != actualJSONSchemaType {
							errors = append(errors,
								fmt.Sprintf("Parser %q/%s metadata_type[%d] %q should convert to json_schema_type %q but found %q",
									c.Name, p.ParserFunction, i, metadataType, expectedJSONSchemaType, actualJSONSchemaType))
						}
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Metadata types and JSON schema types validation failed", strings.Join(errors, "\n"))
	}
}

// convertMetadataTypeToJSONSchemaType converts a metadata type (e.g., "pkg.AlpmDBEntry") to its JSON schema type (e.g., "AlpmDbEntry")
func convertMetadataTypeToJSONSchemaType(metadataType string) string {
	jsonName := packagemetadata.JSONNameFromString(metadataType)
	if jsonName == "" {
		return ""
	}
	return packagemetadata.ToUpperCamelCase(jsonName)
}

// findStructFields extracts field names and types from a struct definition
func findStructFields(file *ast.File, structName string) map[string]string {
	fields := make(map[string]string)

	ast.Inspect(file, func(n ast.Node) bool {
		// look for type declarations
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != structName {
			return true
		}

		// check if it's a struct type
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return false
		}

		// extract field names and types
		for _, field := range structType.Fields.List {
			if len(field.Names) == 0 {
				continue // embedded field
			}

			fieldName := field.Names[0].Name
			fieldType := getTypeName(field.Type)
			fields[fieldName] = fieldType
		}

		return false
	})

	return fields
}

// getTypeName extracts a string representation of a type
func getTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return fmt.Sprintf("%s.%s", getTypeName(t.X), t.Sel.Name)
	case *ast.ArrayType:
		return fmt.Sprintf("[]%s", getTypeName(t.Elt))
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", getTypeName(t.Key), getTypeName(t.Value))
	case *ast.StarExpr:
		return fmt.Sprintf("*%s", getTypeName(t.X))
	default:
		return "unknown"
	}
}

// findMetadataStructFile finds the Go file containing a metadata struct definition
// searches in syft/pkg/*.go for the given struct name
// also handles type aliases and returns the underlying struct name
func findMetadataStructFile(repoRoot, structName string) (filePath string, actualStructName string, err error) {
	pkgDir := filepath.Join(repoRoot, "syft", "pkg")
	files, err := filepath.Glob(filepath.Join(pkgDir, "*.go"))
	if err != nil {
		return "", "", err
	}

	for _, fpath := range files {
		if strings.HasSuffix(fpath, "_test.go") {
			continue
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, fpath, nil, 0)
		if err != nil {
			continue
		}

		// check if this file contains the struct definition or type alias
		found := false
		var resolvedName string
		ast.Inspect(file, func(n ast.Node) bool {
			typeSpec, ok := n.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != structName {
				return true
			}
			// check if it's a struct type
			if _, ok := typeSpec.Type.(*ast.StructType); ok {
				found = true
				resolvedName = structName
				return false
			}
			// check if it's a type alias (e.g., type DpkgArchiveEntry DpkgDBEntry)
			if ident, ok := typeSpec.Type.(*ast.Ident); ok {
				found = true
				resolvedName = ident.Name
				return false
			}
			return true
		})

		if found {
			// if it's a type alias, recursively find the underlying struct
			if resolvedName != structName {
				return findMetadataStructFile(repoRoot, resolvedName)
			}
			return fpath, structName, nil
		}
	}

	return "", "", fmt.Errorf("struct %q not found in syft/pkg/", structName)
}

// parseEvidenceReference parses an evidence string like "StructName.Field" or "StructName.Field1.Field2"
// into struct name and field path components
// examples:
//   - "CondaMetaPackage.MD5" -> ("CondaMetaPackage", []string{"MD5"})
//   - "CondaMetaPackage.PathsData.Paths" -> ("CondaMetaPackage", []string{"PathsData", "Paths"})
//   - "AlpmDBEntry.Files[].Digest" -> ("AlpmDBEntry", []string{"Files", "[]", "Digest"})
func parseEvidenceReference(evidence string) (structName string, fieldPath []string, err error) {
	parts := strings.Split(evidence, ".")
	if len(parts) < 2 {
		return "", nil, fmt.Errorf("invalid evidence format: %q (expected at least StructName.Field)", evidence)
	}

	structName = parts[0]
	// process the remaining parts, splitting on [] for array notation
	for _, part := range parts[1:] {
		// check if this part contains array notation
		if strings.Contains(part, "[]") {
			// split on [] - e.g., "Files[]" becomes ["Files", ""]
			subparts := strings.Split(part, "[]")
			if len(subparts) > 0 && subparts[0] != "" {
				fieldPath = append(fieldPath, subparts[0])
			}
			fieldPath = append(fieldPath, "[]")
		} else {
			fieldPath = append(fieldPath, part)
		}
	}

	return structName, fieldPath, nil
}

// validateFieldPath validates that a field path exists in a struct definition
// handles simple fields, nested fields, and array element fields
// fieldPath can contain "[]" to indicate array dereferencing
func validateFieldPath(repoRoot, structName string, fieldPath []string) error {
	if len(fieldPath) == 0 {
		return fmt.Errorf("empty field path")
	}

	// find the file containing the struct (handles type aliases)
	filePath, actualStructName, err := findMetadataStructFile(repoRoot, structName)
	if err != nil {
		return err
	}

	// parse the file
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", filePath, err)
	}

	// find the struct fields using the actual struct name
	fields := findStructFields(file, actualStructName)
	if len(fields) == 0 {
		return fmt.Errorf("struct %q not found in %s", actualStructName, filePath)
	}

	// validate each component of the field path
	currentFields := fields
	currentStructName := actualStructName
	for i, component := range fieldPath {
		if component == "[]" {
			// array dereference - this is a no-op for validation
			// the previous component should have been an array type
			continue
		}

		fieldType, exists := currentFields[component]
		if !exists {
			return fmt.Errorf("field %q not found in struct %q (path: %s)", component, currentStructName, strings.Join(fieldPath[:i+1], "."))
		}

		// if there are more components, we need to navigate to the next struct
		if i < len(fieldPath)-1 {
			// extract the actual type name, removing pointer/array/slice markers
			typeName := strings.TrimPrefix(fieldType, "*")
			typeName = strings.TrimPrefix(typeName, "[]")

			// if it's not a simple type name (e.g., "CondaPathsData"), skip validation
			// this handles primitive types that don't have further fields
			if strings.Contains(typeName, ".") {
				// qualified type like "pkg.Something" - extract just "Something"
				parts := strings.Split(typeName, ".")
				typeName = parts[len(parts)-1]
			}

			// try to find the nested struct (handles type aliases)
			nestedFilePath, nestedStructName, err := findMetadataStructFile(repoRoot, typeName)
			if err != nil {
				// if we can't find the struct, it might be a primitive or external type
				// we'll allow this to pass
				continue
			}

			nestedFset := token.NewFileSet()
			nestedFile, err := parser.ParseFile(nestedFset, nestedFilePath, nil, 0)
			if err != nil {
				continue
			}

			currentFields = findStructFields(nestedFile, nestedStructName)
			currentStructName = nestedStructName
			if len(currentFields) == 0 {
				// couldn't load the nested struct, but we found the field, so allow it
				continue
			}
		}
	}

	return nil
}

// TestCapabilityEvidenceFieldReferences validates that evidence field references in capabilities
// (e.g., "AlpmDBEntry.Files[].Digests") actually exist on their corresponding metadata structs by using
// AST parsing to verify the field paths, preventing broken references when structs are refactored.
func TestCapabilityEvidenceFieldReferences(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the cataloger/*/capabilities.yaml
	doc, _, err := LoadCapabilities(CatalogerDir(repoRoot), repoRoot)
	require.NoError(t, err)

	// collect all evidence field references
	type evidenceRef struct {
		catalogerName  string
		parserFunction string // empty for cataloger-level
		capabilityName string
		evidenceField  string
	}

	var allReferences []evidenceRef

	// collect from cataloger-level capabilities (custom catalogers)
	for _, cataloger := range doc.Catalogers {
		if cataloger.Type == "custom" && len(cataloger.Capabilities) > 0 {
			for _, capField := range cataloger.Capabilities {
				for _, evidence := range capField.Evidence {
					allReferences = append(allReferences, evidenceRef{
						catalogerName:  cataloger.Name,
						capabilityName: capField.Name,
						evidenceField:  evidence,
					})
				}
			}
		}

		// collect from parser-level capabilities (generic catalogers)
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				if len(parser.Capabilities) > 0 {
					for _, capField := range parser.Capabilities {
						for _, evidence := range capField.Evidence {
							allReferences = append(allReferences, evidenceRef{
								catalogerName:  cataloger.Name,
								parserFunction: parser.ParserFunction,
								capabilityName: capField.Name,
								evidenceField:  evidence,
							})
						}
					}
				}
			}
		}
	}

	// validate each evidence reference
	for _, ref := range allReferences {
		ref := ref // capture for subtest

		// create test name
		testName := ref.catalogerName
		if ref.parserFunction != "" {
			testName = fmt.Sprintf("%s/%s", ref.catalogerName, ref.parserFunction)
		}
		testName = fmt.Sprintf("%s/%s/%s", testName, ref.capabilityName, ref.evidenceField)

		t.Run(testName, func(t *testing.T) {
			// parse the evidence reference
			structName, fieldPath, err := parseEvidenceReference(ref.evidenceField)
			require.NoError(t, err, "failed to parse evidence reference")

			// validate the field path exists
			err = validateFieldPath(repoRoot, structName, fieldPath)
			require.NoError(t, err, "evidence field reference is invalid")
		})
	}
}

// TestDetectorConfigFieldReferences validates that config field names referenced in detector conditions
// actually exist in the cataloger's config struct, ensuring that conditional detectors can properly
// evaluate their activation conditions based on configuration.
func TestDetectorConfigFieldReferences(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the cataloger/*/capabilities.yaml
	doc, _, err := LoadCapabilities(CatalogerDir(repoRoot), repoRoot)
	require.NoError(t, err)

	// collect all validation errors before failing
	var errors []string

	// check each cataloger's detectors
	for _, cataloger := range doc.Catalogers {
		if cataloger.Type != "custom" {
			continue // only custom catalogers have detectors
		}

		for detectorIdx, detector := range cataloger.Detectors {
			// if detector has no conditions, skip validation
			if len(detector.Conditions) == 0 {
				continue
			}

			// detector has conditions - cataloger must have a config
			if cataloger.Config == "" {
				errors = append(errors,
					fmt.Sprintf("Cataloger %q detector %d has conditions but cataloger has no config struct",
						cataloger.Name, detectorIdx))
				continue
			}

			// load the cataloger's config struct
			configEntry, exists := doc.Configs[cataloger.Config]
			if !exists {
				errors = append(errors,
					fmt.Sprintf("Cataloger %q references config %q which doesn't exist",
						cataloger.Name, cataloger.Config))
				continue
			}

			// build a set of valid config field names
			validFields := make(map[string]bool)
			for _, field := range configEntry.Fields {
				validFields[field.Key] = true
			}

			// validate each condition
			for condIdx, condition := range detector.Conditions {
				for fieldName := range condition.When {
					if !validFields[fieldName] {
						errors = append(errors,
							fmt.Sprintf("Cataloger %q detector %d condition %d references config field %q which doesn't exist in config struct %q",
								cataloger.Name, detectorIdx, condIdx, fieldName, cataloger.Config))
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Detector config field reference validation failed", strings.Join(errors, "\n"))
	}
}

// TestCatalogersInSync ensures that all catalogers from the syft binary are documented in cataloger/*/capabilities.yaml
// and vice versa, and that all capability fields are properly filled without TODOs or null values.
func TestCatalogersInSync(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	// get canonical list from syft binary
	catalogersInBinary := getCatalogerNamesFromBinary(t)

	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	yamlCatalogers := strset.New()
	for _, c := range catalogerEntries {
		yamlCatalogers.Add(c.Name)
	}

	// test 1: All catalogers in binary must be in YAML
	var missingFromYAML []string
	for _, name := range catalogersInBinary {
		if !yamlCatalogers.Has(name) {
			missingFromYAML = append(missingFromYAML, name)
		}
	}
	require.Empty(t, missingFromYAML,
		"The following catalogers are in 'syft cataloger list' but missing from capabilities YAML: %v\n"+
			"Run 'go generate ./internal/capabilities' to auto-add generic catalogers, or manually add custom catalogers.",
		missingFromYAML)

	// test 2: All catalogers in YAML must exist in binary
	var orphanedInYAML []string
	binarySet := strset.New()
	for _, name := range catalogersInBinary {
		binarySet.Add(name)
	}
	for _, name := range yamlCatalogers.List() {
		if !binarySet.Has(name) {
			orphanedInYAML = append(orphanedInYAML, name)
		}
	}
	require.Empty(t, orphanedInYAML,
		"The following catalogers are in capabilities YAML but not found in binary: %v\n"+
			"These catalogers may have been removed. Delete them from the YAML.",
		orphanedInYAML)

	// test 3: All capabilities must be filled (no TODOs/nulls)
	validateCapabilitiesFilled(t, catalogerEntries)
}

func getCatalogerNamesFromBinary(t *testing.T) []string {
	checkCompletenessTestsEnabled(t)

	// get cataloger names from task factories
	infos, err := AllPackageCatalogerInfo()
	require.NoError(t, err)

	var names []string
	for _, info := range infos {
		names = append(names, info.Name)
	}

	sort.Strings(names)
	return names
}

func validateCapabilitiesFilled(t *testing.T, catalogers []capabilities.CatalogerEntry) {
	checkCompletenessTestsEnabled(t)

	for _, c := range catalogers {
		c := c // capture loop variable for subtest

		t.Run(c.Name, func(t *testing.T) {
			if c.Type == "generic" {
				// generic catalogers have parsers with capabilities
				require.NotEmpty(t, c.Parsers, "generic cataloger must have at least one parser")

				for _, p := range c.Parsers {
					p := p // capture loop variable for subtest

					t.Run(p.ParserFunction, func(t *testing.T) {
						require.NotEmpty(t, p.Capabilities, "parser must have at least one capability field defined")
					})
				}
			} else if c.Type == "custom" {
				// custom catalogers have cataloger-level capabilities
				require.NotEmpty(t, c.Capabilities, "custom cataloger must have at least one capability field defined")
			}
		})
	}
}

// TestPackageTypeCoverage ensures that every package type defined in pkg.AllPkgs is represented in at least
// one cataloger's capabilities, preventing orphaned package types that are defined but never documented.
func TestPackageTypeCoverage(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// collect all package types mentioned in catalogers
	foundPkgTypes := strset.New()
	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				for _, pkgType := range parser.PackageTypes {
					foundPkgTypes.Add(pkgType)
				}
			}
		} else if cataloger.Type == "custom" {
			for _, pkgType := range cataloger.PackageTypes {
				foundPkgTypes.Add(pkgType)
			}
		}
	}

	// check that all known package types are represented
	var missingTypes []pkg.Type
	for _, pkgType := range pkg.AllPkgs {
		if !foundPkgTypes.Has(string(pkgType)) {
			missingTypes = append(missingTypes, pkgType)
		}
	}

	// filter out exceptions
	var missingTypesWithoutExceptions []pkg.Type
	for _, pkgType := range missingTypes {
		if !packageTypeCoverageExceptions.Has(string(pkgType)) {
			missingTypesWithoutExceptions = append(missingTypesWithoutExceptions, pkgType)
		}
	}

	require.Empty(t, missingTypesWithoutExceptions,
		"The following package types are not represented in any cataloger: %v\n"+
			"Either add catalogers for these types or update pkg.AllPkgs if they're no longer supported.",
		missingTypesWithoutExceptions)
}

// TestMetadataTypeCoverage ensures that every metadata type defined in packagemetadata.AllTypes() is represented
// in at least one cataloger's capabilities, preventing orphaned metadata types that are defined but never produced.
func TestMetadataTypeCoverage(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// collect all metadata types mentioned in catalogers
	foundMetadataTypes := strset.New()
	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "generic" {
			for _, p := range cataloger.Parsers {
				for _, metadataType := range p.MetadataTypes {
					foundMetadataTypes.Add(strings.TrimPrefix(metadataType, "pkg."))
				}
			}
		} else if cataloger.Type == "custom" {
			for _, metadataType := range cataloger.MetadataTypes {
				foundMetadataTypes.Add(strings.TrimPrefix(metadataType, "pkg."))
			}
		}
	}

	// get all known metadata types
	allMetadataTypes := packagemetadata.AllTypes()

	// check that all known metadata types are represented
	var missingTypes []string
	for _, metadataType := range allMetadataTypes {
		typeName := reflect.TypeOf(metadataType).Name()
		if !foundMetadataTypes.Has(typeName) {
			missingTypes = append(missingTypes, typeName)
		}
	}

	// filter out exceptions
	var missingTypesWithoutExceptions []string
	for _, metadataType := range missingTypes {
		if !metadataTypeCoverageExceptions.Has(metadataType) {
			missingTypesWithoutExceptions = append(missingTypesWithoutExceptions, metadataType)
		}
	}

	require.Empty(t, missingTypesWithoutExceptions,
		"The following metadata types are not represented in any cataloger: %v\n"+
			"Either add catalogers for these types or update packagemetadata.AllTypes() if they're no longer supported.",
		missingTypesWithoutExceptions)
}

// TestCatalogerStructure validates that catalogers follow structural conventions: generic catalogers must have
// parsers and parser-level capabilities, custom catalogers must have detectors and cataloger-level capabilities,
// and all catalogers must have an ecosystem set.
func TestCatalogerStructure(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	for _, c := range catalogerEntries {
		c := c // capture loop variable for subtest

		t.Run(c.Name, func(t *testing.T) {
			// ecosystem must always be set (it's MANUAL)
			require.NotEmpty(t, c.Ecosystem, "ecosystem must be set for all catalogers")

			if c.Type == "generic" {
				// generic catalogers must have parsers
				require.NotEmpty(t, c.Parsers, "generic cataloger must have at least one parser")

				// generic catalogers should not have cataloger-level capabilities
				require.Empty(t, c.Capabilities, "generic cataloger should not have cataloger-level capabilities (use parser-level instead)")

				// generic catalogers should not have cataloger-level metadata/package types
				require.Empty(t, c.MetadataTypes, "generic cataloger should not have cataloger-level metadata types")
				require.Empty(t, c.PackageTypes, "generic cataloger should not have cataloger-level package types")
			} else if c.Type == "custom" {
				// custom catalogers must have detectors
				require.NotEmpty(t, c.Detectors, "custom cataloger must have at least one detector")

				// custom catalogers must have cataloger-level capabilities
				require.NotEmpty(t, c.Capabilities, "custom cataloger must have cataloger-level capabilities")

				// custom catalogers should not have parsers
				require.Empty(t, c.Parsers, "custom cataloger should not have parsers (those are for generic catalogers)")
			} else {
				t.Errorf("unknown cataloger type: %q (must be 'generic' or 'custom')", c.Type)
			}
		})
	}
}

// TestCatalogerDataQuality checks for data integrity issues in cataloger/*/capabilities.yaml, including duplicate cataloger
// names, duplicate parser functions within catalogers, and validates that detector definitions are well-formed.
func TestCatalogerDataQuality(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	t.Run("no duplicate cataloger names", func(t *testing.T) {
		nameCount := make(map[string]int)
		for _, cataloger := range catalogerEntries {
			nameCount[cataloger.Name]++
		}

		var duplicates []string
		for name, count := range nameCount {
			if count > 1 {
				duplicates = append(duplicates, fmt.Sprintf("%s (appears %d times)", name, count))
			}
		}

		require.Empty(t, duplicates, "Found duplicate cataloger names: %v", duplicates)
	})

	t.Run("detector validation for custom catalogers", func(t *testing.T) {
		for _, c := range catalogerEntries {
			if c.Type != "custom" {
				continue
			}

			c := c // capture loop variable

			t.Run(c.Name, func(t *testing.T) {
				require.NotEmpty(t, c.Detectors, "custom cataloger must have at least one detector")

				for i, detector := range c.Detectors {
					t.Run(fmt.Sprintf("detector-%d", i), func(t *testing.T) {
						// detector criteria must not be empty
						require.NotEmpty(t, detector.Criteria, "detector criteria must not be empty")

						// detector method must be valid
						validMethods := map[capabilities.ArtifactDetectionMethod]bool{
							capabilities.GlobDetection:     true,
							capabilities.PathDetection:     true,
							capabilities.MIMETypeDetection: true,
						}
						require.True(t, validMethods[detector.Method],
							"detector method must be one of: glob, path, mimetype (got %q)", detector.Method)
					})
				}
			})
		}
	})

	t.Run("no duplicate parser functions within cataloger", func(t *testing.T) {
		for _, c := range catalogerEntries {
			if c.Type != "generic" {
				continue
			}

			c := c // capture loop variable

			t.Run(c.Name, func(t *testing.T) {
				parserFuncs := strset.New()
				var duplicates []string

				for _, p := range c.Parsers {
					if parserFuncs.Has(p.ParserFunction) {
						duplicates = append(duplicates, p.ParserFunction)
					}
					parserFuncs.Add(p.ParserFunction)
				}

				require.Empty(t, duplicates, "Found duplicate parser functions: %v", duplicates)
			})
		}
	})
}

// TestCatalogersHaveTestObservations ensures that all custom catalogers (and optionally parsers) have
// test observations recorded in test-fixtures/test-observations.json, which proves they are using the
// pkgtest.CatalogTester helpers and have test coverage.
func TestCatalogersHaveTestObservations(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load catalogers from YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// collect all catalogers and parsers from observations
	observedCatalogers := strset.New()
	observedParsers := make(map[string]*strset.Set) // package -> parser set

	// walk test-fixtures directories to find test-observations.json files
	testFixtureDirs, err := FindTestFixtureDirs(repoRoot)
	require.NoError(t, err)

	for _, dir := range testFixtureDirs {
		observationsFile := filepath.Join(dir, "test-observations.json")
		if _, err := os.Stat(observationsFile); os.IsNotExist(err) {
			continue
		}

		observations, err := ReadTestObservations(observationsFile)
		if err != nil {
			t.Logf("Warning: failed to read %s: %v", observationsFile, err)
			continue
		}

		// track observed catalogers
		for catalogerName := range observations.Catalogers {
			observedCatalogers.Add(catalogerName)
		}

		// track observed parsers
		p := observations.Package
		if observedParsers[p] == nil {
			observedParsers[p] = strset.New()
		}
		for parserName := range observations.Parsers {
			observedParsers[p].Add(parserName)
		}
	}

	// infer parser observations for single-parser catalogers
	// if a cataloger has only one parser and the cataloger was observed, assume the parser was evaluated
	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "generic" && len(cataloger.Parsers) == 1 && observedCatalogers.Has(cataloger.Name) {
			packageName := extractPackageName(cataloger.Name)
			if observedParsers[packageName] == nil {
				observedParsers[packageName] = strset.New()
			}
			observedParsers[packageName].Add(cataloger.Parsers[0].ParserFunction)
		}
	}

	// verify catalogers have observations
	var missingCatalogers []string
	var missingParsers []string

	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "custom" {
			// custom catalogers should always have cataloger-level observations
			// skip if this cataloger has an exception (nil or non-nil)
			if _, hasException := observationExceptions[cataloger.Name]; hasException {
				continue
			}
			if !observedCatalogers.Has(cataloger.Name) {
				missingCatalogers = append(missingCatalogers, cataloger.Name)
			}
		} else if cataloger.Type == "generic" && requireParserObservations {
			// generic catalogers have parser-level observations (only checked if requireParserObservations=true)
			// skip if the cataloger itself has an exception (applies to all its parsers)
			if _, hasException := observationExceptions[cataloger.Name]; hasException {
				continue
			}

			// extract package name from cataloger name
			packageName := extractPackageName(cataloger.Name)

			for _, p := range cataloger.Parsers {
				parserKey := fmt.Sprintf("%s/%s", cataloger.Name, p.ParserFunction)
				// skip if this specific parser has an exception (nil or non-nil)
				if _, hasException := observationExceptions[parserKey]; hasException {
					continue
				}
				if observedParsers[packageName] == nil || !observedParsers[packageName].Has(p.ParserFunction) {
					missingParsers = append(missingParsers, parserKey)
				}
			}
		}
	}

	require.Empty(t, missingCatalogers,
		"The following custom catalogers have no test observations (not using pkgtest helpers): %v\n"+
			"Update tests to use CatalogTester.TestCataloger() from syft/pkg/cataloger/internal/pkgtest",
		missingCatalogers)

	if requireParserObservations {
		require.Empty(t, missingParsers,
			"The following parsers have no test observations (not using pkgtest helpers): %v\n"+
				"Update tests to use CatalogTester.TestParser() from syft/pkg/cataloger/internal/pkgtest",
			missingParsers)
	}
}

// extractPackageName extracts the package name from a cataloger name
// e.g., "javascript-lock-cataloger" -> "javascript"
func extractPackageName(catalogerName string) string {
	// package name is the first segment before the first dash
	for i, ch := range catalogerName {
		if ch == '-' {
			return catalogerName[:i]
		}
	}
	return catalogerName
}
