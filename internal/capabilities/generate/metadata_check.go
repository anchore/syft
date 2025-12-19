// this file validates that all known metadata and package types are documented in cataloger/*/capabilities.yaml by checking coverage and reporting any missing types.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/capabilities/internal"
)

var (
	warningStyleMeta = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true) // yellow
	dimStyleMeta     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))           // lighter grey (256-color)

	// exceptions for metadata types that are intentionally not referenced in cataloger/*/capabilities.yaml
	metadataTypeExceptions = map[string]bool{
		"pkg.MicrosoftKbPatch": true,
	}

	// exceptions for package types that are intentionally not referenced in cataloger/*/capabilities.yaml
	packageTypeExceptions = map[string]bool{
		"jenkins-plugin": true,
		"msrc-kb":        true,
	}
)

// parsePackageMetadataTypes parses packagemetadata/generated.go and extracts all metadata type names
// from the AllTypes() function (e.g., "pkg.AlpmDBEntry", "pkg.ApkDBEntry", etc.)
func parsePackageMetadataTypes(repoRoot string) ([]string, error) {
	metadataFile := filepath.Join(repoRoot, "internal", "packagemetadata", "generated.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, metadataFile, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", metadataFile, err)
	}

	var types []string

	// find the AllTypes function
	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Name.Name != "AllTypes" {
			continue
		}

		// walk the function body to find return statement
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			returnStmt, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}

			// should have one return value: []any{...}
			if len(returnStmt.Results) != 1 {
				return true
			}

			// parse the composite literal (slice)
			compositeLit, ok := returnStmt.Results[0].(*ast.CompositeLit)
			if !ok {
				return true
			}

			// extract each element (should be pkg.TypeName{})
			for _, elt := range compositeLit.Elts {
				if typeExpr, ok := elt.(*ast.CompositeLit); ok {
					typeName := extractTypeName(typeExpr.Type)
					if typeName != "" {
						types = append(types, typeName)
					}
				}
			}

			return false
		})
	}

	return types, nil
}

// extractTypeName extracts the full type name from an AST type expression
// e.g., pkg.AlpmDBEntry -> "pkg.AlpmDBEntry"
func extractTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		// pkg.TypeName
		if pkgIdent, ok := t.X.(*ast.Ident); ok {
			return fmt.Sprintf("%s.%s", pkgIdent.Name, t.Sel.Name)
		}
	case *ast.Ident:
		// just TypeName
		return t.Name
	}
	return ""
}

// collectReferencedMetadataTypes walks through all catalogers and collects
// all metadata types referenced in parser and cataloger-level metadata_types fields
func collectReferencedMetadataTypes(doc *capabilities.Document) []string {
	typeSet := make(map[string]bool)

	for _, cataloger := range doc.Catalogers {
		// collect from parsers (for generic catalogers)
		for _, parser := range cataloger.Parsers {
			for _, metadataType := range parser.MetadataTypes {
				typeSet[metadataType] = true
			}
		}

		// collect from cataloger-level metadata_types (for custom catalogers)
		for _, metadataType := range cataloger.MetadataTypes {
			typeSet[metadataType] = true
		}
	}

	// convert set to sorted slice
	var types []string
	for typeName := range typeSet {
		types = append(types, typeName)
	}
	sort.Strings(types)

	return types
}

// checkMetadataTypeCoverage compares metadata types from packagemetadata/generated.go
// with types referenced in cataloger/*/capabilities.yaml and returns unreferenced types
func checkMetadataTypeCoverage(capabilitiesDir string, repoRoot string) ([]string, error) {
	// parse packagemetadata/generated.go to get all types
	allTypes, err := parsePackageMetadataTypes(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to parse package metadata types: %w", err)
	}

	// load capabilities files to get referenced types
	doc, _, err := internal.LoadCapabilities(capabilitiesDir, repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to load capabilities files: %w", err)
	}

	referencedTypes := collectReferencedMetadataTypes(doc)

	// create a set of referenced types for quick lookup
	referencedSet := make(map[string]bool)
	for _, typeName := range referencedTypes {
		referencedSet[typeName] = true
	}

	// find unreferenced types (excluding exceptions)
	var unreferenced []string
	for _, typeName := range allTypes {
		if !referencedSet[typeName] && !metadataTypeExceptions[typeName] {
			unreferenced = append(unreferenced, typeName)
		}
	}

	return unreferenced, nil
}

// printMetadataTypeCoverageWarning prints a warning if there are metadata types
// from packagemetadata/generated.go that aren't referenced in cataloger/*/capabilities.yaml
func printMetadataTypeCoverageWarning(capabilitiesDir string, repoRoot string) {
	unreferenced, err := checkMetadataTypeCoverage(capabilitiesDir, repoRoot)
	if err != nil {
		// don't fail generation, just skip the check
		fmt.Printf("%s Could not check metadata type coverage: %v\n", warningStyleMeta.Render("⚠"), err)
		return
	}

	if len(unreferenced) > 0 {
		fmt.Println()
		fmt.Printf("%s %s metadata types from packagemetadata are not referenced in cataloger/*/capabilities.yaml:\n",
			warningStyleMeta.Render("⚠ INFO:"),
			warningStyleMeta.Render(fmt.Sprintf("%d", len(unreferenced))))
		for _, typeName := range unreferenced {
			// extract just the type name without "pkg." prefix for cleaner output
			shortName := strings.TrimPrefix(typeName, "pkg.")
			fmt.Printf("  - %s\n", dimStyleMeta.Render(shortName))
		}
		fmt.Println()
		fmt.Println(dimStyleMeta.Render("These types may be:"))
		fmt.Println(dimStyleMeta.Render("  • Used in custom catalogers (which don't have metadata_types)"))
		fmt.Println(dimStyleMeta.Render("  • Deprecated or unused"))
		fmt.Println(dimStyleMeta.Render("  • Missing from cataloger pattern documentation"))
	}
}

// parseConstValues extracts constant names to their string values from an AST file
func parseConstValues(f *ast.File) map[string]string {
	constValues := make(map[string]string)
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, ident := range valueSpec.Names {
				if i < len(valueSpec.Values) {
					if lit, ok := valueSpec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						constValues[ident.Name] = strings.Trim(lit.Value, `"`)
					}
				}
			}
		}
	}
	return constValues
}

// extractTypesFromCompositeLit extracts package type names from a composite literal
func extractTypesFromCompositeLit(compositeLit *ast.CompositeLit, constValues map[string]string) []string {
	var types []string
	for _, elt := range compositeLit.Elts {
		if ident, ok := elt.(*ast.Ident); ok {
			// look up the string value for this constant
			if typeName, ok := constValues[ident.Name]; ok && typeName != "UnknownPackage" {
				types = append(types, typeName)
			}
		}
	}
	return types
}

// extractAllPkgsTypes finds the AllPkgs variable and extracts package type names
func extractAllPkgsTypes(f *ast.File, constValues map[string]string) []string {
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for i, ident := range valueSpec.Names {
				if ident.Name == "AllPkgs" && i < len(valueSpec.Values) {
					// found AllPkgs, extract the slice elements
					compositeLit, ok := valueSpec.Values[i].(*ast.CompositeLit)
					if !ok {
						continue
					}
					return extractTypesFromCompositeLit(compositeLit, constValues)
				}
			}
		}
	}

	return []string{}
}

// parseAllPackageTypes parses syft/pkg/type.go and extracts all package type names
// from the AllPkgs variable by looking up their const string values
func parseAllPackageTypes(repoRoot string) ([]string, error) {
	typeFile := filepath.Join(repoRoot, "syft", "pkg", "type.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, typeFile, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", typeFile, err)
	}

	// first, build a map of constant names to their string values
	constValues := parseConstValues(f)

	// find the AllPkgs variable and extract types
	types := extractAllPkgsTypes(f, constValues)

	return types, nil
}

// collectReferencedPackageTypes walks through all catalogers and collects
// all package types referenced in parser and cataloger-level package_types fields
func collectReferencedPackageTypes(doc *capabilities.Document) []string {
	typeSet := make(map[string]bool)

	for _, cataloger := range doc.Catalogers {
		// collect from parsers (for generic catalogers)
		for _, parser := range cataloger.Parsers {
			for _, pkgType := range parser.PackageTypes {
				typeSet[pkgType] = true
			}
		}

		// collect from cataloger-level package_types (for custom catalogers)
		for _, pkgType := range cataloger.PackageTypes {
			typeSet[pkgType] = true
		}
	}

	// convert set to sorted slice
	var types []string
	for typeName := range typeSet {
		types = append(types, typeName)
	}
	sort.Strings(types)

	return types
}

// checkPackageTypeCoverage compares package types from pkg.AllPkgs
// with types referenced in cataloger/*/capabilities.yaml and returns unreferenced types
func checkPackageTypeCoverage(capabilitiesDir string, repoRoot string) ([]string, error) {
	// parse pkg/type.go to get all package types
	allTypes, err := parseAllPackageTypes(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to parse package types: %w", err)
	}

	// load capabilities files to get referenced types
	doc, _, err := internal.LoadCapabilities(capabilitiesDir, repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to load capabilities files: %w", err)
	}

	referencedTypes := collectReferencedPackageTypes(doc)

	// create a set of referenced types for quick lookup
	referencedSet := make(map[string]bool)
	for _, typeName := range referencedTypes {
		referencedSet[typeName] = true
	}

	// find unreferenced types (excluding exceptions)
	var unreferenced []string
	for _, typeName := range allTypes {
		if !referencedSet[typeName] && !packageTypeExceptions[typeName] {
			unreferenced = append(unreferenced, typeName)
		}
	}

	return unreferenced, nil
}

// printPackageTypeCoverageWarning prints a warning if there are package types
// from pkg.AllPkgs that aren't referenced in cataloger/*/capabilities.yaml
func printPackageTypeCoverageWarning(capabilitiesDir string, repoRoot string) {
	unreferenced, err := checkPackageTypeCoverage(capabilitiesDir, repoRoot)
	if err != nil {
		// don't fail generation, just skip the check
		fmt.Printf("%s Could not check package type coverage: %v\n", warningStyleMeta.Render("⚠"), err)
		return
	}

	if len(unreferenced) > 0 {
		fmt.Println()
		fmt.Printf("%s %s package types from pkg.AllPkgs are not referenced in cataloger/*/capabilities.yaml:\n",
			warningStyleMeta.Render("⚠ WARNING:"),
			warningStyleMeta.Render(fmt.Sprintf("%d", len(unreferenced))))
		for _, typeName := range unreferenced {
			fmt.Printf("  - %s\n", dimStyleMeta.Render(typeName))
		}
		fmt.Println()
		fmt.Println(dimStyleMeta.Render("These package types should be documented in cataloger/*/capabilities.yaml."))
		fmt.Println(dimStyleMeta.Render("If a package type is not emitted by any cataloger, it may be deprecated or unused."))
	}
}
