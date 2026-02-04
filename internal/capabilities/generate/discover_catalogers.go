// this file discovers generic catalogers from source code by walking syft/pkg/cataloger/ and using AST parsing to find generic.NewCataloger() calls and extract parser information.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
)

// DiscoveredCataloger represents a cataloger discovered by parsing source code
type DiscoveredCataloger struct {
	Name           string
	Type           string // "generic" or "custom"
	PackageName    string // e.g., "python", "swift" - extracted from source file path
	SourceFile     string
	SourceFunction string
	Parsers        []DiscoveredParser // only for generic catalogers
}

// DiscoveredParser represents a parser function and its detection criteria discovered from source
type DiscoveredParser struct {
	ParserFunction  string
	Method          capabilities.ArtifactDetectionMethod
	Criteria        []string
	MetadataTypes   []string // populated from cataloger-type-uses.json files
	PackageTypes    []string // populated from cataloger-type-uses.json files
	JSONSchemaTypes []string // populated from MetadataTypes
}

// discoverGenericCatalogers finds all uses of generic.NewCataloger() in the codebase
// Returns map[catalogerName]DiscoveredCataloger
func discoverGenericCatalogers(repoRoot string) (map[string]DiscoveredCataloger, error) {
	catalogerRoot := filepath.Join(repoRoot, "syft", "pkg", "cataloger")

	// find all .go files under syft/pkg/cataloger/ recursively
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

	discovered := make(map[string]DiscoveredCataloger)

	for _, file := range files {
		catalogers, err := discoverGenericCatalogersInFile(file, repoRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}

		for name, cataloger := range catalogers {
			if existing, ok := discovered[name]; ok {
				return nil, fmt.Errorf("duplicate cataloger name %q found in %s and %s", name, existing.SourceFile, cataloger.SourceFile)
			}
			discovered[name] = cataloger
		}
	}

	return discovered, nil
}

func discoverGenericCatalogersInFile(path, repoRoot string) (map[string]DiscoveredCataloger, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	discovered := make(map[string]DiscoveredCataloger)

	// find all function declarations
	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		// check if function name matches New*Cataloger pattern
		if !strings.HasPrefix(funcDecl.Name.Name, "New") || !strings.HasSuffix(funcDecl.Name.Name, "Cataloger") {
			continue
		}

		// check if return type is pkg.Cataloger
		if !returnsPackageCataloger(funcDecl) {
			continue
		}

		// parse the function body to find generic.NewCataloger calls
		cataloger, err := parseGenericCatalogerFunction(funcDecl, path, repoRoot)
		if err != nil {
			// not a generic cataloger, skip
			continue
		}

		if cataloger != nil {
			discovered[cataloger.Name] = *cataloger
		}
	}

	return discovered, nil
}

func returnsPackageCataloger(funcDecl *ast.FuncDecl) bool {
	if funcDecl.Type.Results == nil || len(funcDecl.Type.Results.List) != 1 {
		return false
	}

	// check if the return type is pkg.Cataloger or just Cataloger
	returnType := funcDecl.Type.Results.List[0].Type
	selector, ok := returnType.(*ast.SelectorExpr)
	if !ok {
		// might be just "Cataloger" without package prefix
		ident, ok := returnType.(*ast.Ident)
		return ok && ident.Name == "Cataloger"
	}

	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}

	return pkg.Name == "pkg" && selector.Sel.Name == "Cataloger"
}

func parseGenericCatalogerFunction(funcDecl *ast.FuncDecl, filePath, repoRoot string) (*DiscoveredCataloger, error) {
	if funcDecl.Body == nil {
		return nil, fmt.Errorf("function has no body")
	}

	// parse the file again to get imports and constants context
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	ctx := &parseContext{
		file:     f,
		filePath: filePath,
		repoRoot: repoRoot,
	}

	var catalogerName string
	var parsers []DiscoveredParser

	// walk the function body to find generic.NewCataloger call
	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		// look for call expressions
		callExpr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// check if this is a call to generic.NewCataloger
		if isGenericNewCatalogerCall(callExpr) {
			// extract the cataloger name from the first argument
			if len(callExpr.Args) > 0 {
				// handle string literals
				if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					catalogerName = strings.Trim(lit.Value, `"`)
				}
				// handle constant identifiers
				if ident, ok := callExpr.Args[0].(*ast.Ident); ok {
					catalogerName = resolveLocalConstant(ident.Name, ctx)
				}
			}
		}

		// check if this is a WithParserBy* call
		if p := parseWithParserByCall(callExpr, ctx); p != nil {
			parsers = append(parsers, *p)
		}

		return true
	})

	if catalogerName == "" {
		// not a generic cataloger
		return nil, fmt.Errorf("no generic.NewCataloger call found")
	}

	// make file path relative to repo root
	relPath, err := filepath.Rel(repoRoot, filePath)
	if err != nil {
		relPath = filePath
	}

	return &DiscoveredCataloger{
		Name:           catalogerName,
		Type:           genericCatalogerType,
		PackageName:    extractPackageNameFromPath(relPath),
		SourceFile:     relPath,
		SourceFunction: funcDecl.Name.Name,
		Parsers:        parsers,
	}, nil
}

// extractPackageNameFromPath extracts the package name from a cataloger source file path
// e.g., "syft/pkg/cataloger/swift/cataloger.go" -> "swift"
func extractPackageNameFromPath(filePath string) string {
	parts := strings.Split(filePath, string(filepath.Separator))

	// find the LAST occurrence of "cataloger" in the path
	// (to handle test fixtures with multiple "cataloger" segments)
	lastCatalogerIndex := -1
	for i, part := range parts {
		if part == "cataloger" {
			lastCatalogerIndex = i
		}
	}

	if lastCatalogerIndex != -1 && lastCatalogerIndex+1 < len(parts) {
		// return the next segment after the last "cataloger"
		return parts[lastCatalogerIndex+1]
	}

	return ""
}

func isGenericNewCatalogerCall(callExpr *ast.CallExpr) bool {
	selector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}

	return pkg.Name == "generic" && selector.Sel.Name == "NewCataloger"
}

type parseContext struct {
	file     *ast.File
	filePath string
	repoRoot string
}

func parseWithParserByCall(callExpr *ast.CallExpr, ctx *parseContext) *DiscoveredParser {
	selector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	methodName := selector.Sel.Name

	var method capabilities.ArtifactDetectionMethod
	switch {
	case strings.HasPrefix(methodName, "WithParserByGlobs"):
		method = capabilities.GlobDetection
	case strings.HasPrefix(methodName, "WithParserByPath"):
		method = capabilities.PathDetection
	case strings.HasPrefix(methodName, "WithParserByMimeTypes"):
		method = capabilities.MIMETypeDetection
	default:
		return nil
	}

	if len(callExpr.Args) < 2 {
		return nil
	}

	// first argument is the parser function name
	var parserFunction string
	switch arg := callExpr.Args[0].(type) {
	case *ast.Ident:
		// simple identifier: parseFunc
		parserFunction = arg.Name
	case *ast.SelectorExpr:
		// selector expression: adapter.parseFunc
		parserFunction = arg.Sel.Name
	default:
		return nil
	}

	// remaining arguments are detection criteria (can be string literals, constants, or method calls)
	var criteria []string
	for _, arg := range callExpr.Args[1:] {
		values := resolveCriteriaValues(arg, ctx)
		criteria = append(criteria, values...)
	}

	if len(criteria) == 0 {
		return nil
	}

	return &DiscoveredParser{
		ParserFunction: parserFunction,
		Method:         method,
		Criteria:       criteria,
	}
}

// resolveCriteriaValues resolves criteria argument(s) to string value(s)
// handles string literals, constants, and method calls like .List()
func resolveCriteriaValues(arg ast.Expr, ctx *parseContext) []string {
	switch expr := arg.(type) {
	case *ast.BasicLit:
		// direct string literal
		if expr.Kind == token.STRING {
			value := strings.Trim(expr.Value, `"`)
			if value != "" {
				return []string{value}
			}
		}

	case *ast.Ident:
		// local constant reference
		value := resolveLocalConstant(expr.Name, ctx)
		if value != "" {
			return []string{value}
		}

	case *ast.SelectorExpr:
		// imported constant reference (e.g., pkg.ApkDBGlob)
		if pkgIdent, ok := expr.X.(*ast.Ident); ok {
			value := resolveImportedConstant(pkgIdent.Name, expr.Sel.Name, ctx)
			if value != "" {
				return []string{value}
			}
		}

	case *ast.CallExpr:
		// method call like mimetype.ExecutableMIMETypeSet.List()
		return resolveMethodCallValues(expr, ctx)
	}

	return nil
}

// resolveMethodCallValues resolves method calls that return string slices
// specifically handles .List() calls on string sets
func resolveMethodCallValues(callExpr *ast.CallExpr, ctx *parseContext) []string {
	// check if this is a .List() method call
	selector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "List" {
		return nil
	}

	// get the receiver (e.g., mimetype.ExecutableMIMETypeSet from mimetype.ExecutableMIMETypeSet.List())
	var pkgName, varName string

	switch recv := selector.X.(type) {
	case *ast.SelectorExpr:
		// format: package.Variable (e.g., mimetype.ExecutableMIMETypeSet)
		if pkgIdent, ok := recv.X.(*ast.Ident); ok {
			pkgName = pkgIdent.Name
			varName = recv.Sel.Name
		}
	case *ast.Ident:
		// format: Variable (local variable)
		varName = recv.Name
	}

	if varName == "" {
		return nil
	}

	// try to resolve the variable to its declaration and extract the string slice
	if pkgName != "" {
		// imported variable (e.g., mimetype.ExecutableMIMETypeSet)
		return resolveImportedVariable(pkgName, varName, ctx)
	}

	// local variable
	return resolveLocalVariable(varName, ctx)
}

// resolveImportedVariable finds a variable in an imported package and extracts its string slice values
func resolveImportedVariable(pkgName, varName string, ctx *parseContext) []string {
	// find the import path for this package
	var importPath string
	for _, imp := range ctx.file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)

		if imp.Name != nil && imp.Name.Name == pkgName {
			importPath = path
			break
		}

		parts := strings.Split(path, "/")
		if len(parts) > 0 && parts[len(parts)-1] == pkgName {
			importPath = path
			break
		}
	}

	if importPath == "" {
		return nil
	}

	// resolve import path to file system path
	pkgDir := resolveImportPath(importPath, ctx.repoRoot)
	if pkgDir == "" {
		return nil
	}

	// find the variable in the package and extract string slice
	return findVariableStringSlice(pkgDir, varName)
}

// resolveLocalVariable finds a local variable and extracts its string slice values
func resolveLocalVariable(varName string, ctx *parseContext) []string {
	return extractStringSliceFromFile(ctx.file, varName)
}

// findVariableStringSlice searches for a variable in a package directory and extracts its string slice
func findVariableStringSlice(pkgDir, varName string) []string {
	files, err := filepath.Glob(filepath.Join(pkgDir, "*.go"))
	if err != nil {
		return nil
	}

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			continue
		}

		if values := extractStringSliceFromFile(f, varName); len(values) > 0 {
			return values
		}
	}

	return nil
}

// extractStringSliceFromFile extracts string values from a variable declaration like:
// var Foo = strset.New([]string{"a", "b", "c"}...)
func extractStringSliceFromFile(file *ast.File, varName string) []string {
	for _, decl := range file.Decls {
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
				if ident.Name == varName && i < len(valueSpec.Values) {
					return extractStringSliceFromExpr(valueSpec.Values[i])
				}
			}
		}
	}

	return nil
}

// extractStringSliceFromExpr extracts string literals from expressions like:
// strset.New([]string{"a", "b"}...)
func extractStringSliceFromExpr(expr ast.Expr) []string {
	// handle strset.New(...) calls
	callExpr, ok := expr.(*ast.CallExpr)
	if !ok || len(callExpr.Args) == 0 {
		return nil
	}

	// get the first argument (should be a composite literal with strings)
	arg := callExpr.Args[0]

	// handle []string{...} composite literals
	compositeLit, ok := arg.(*ast.CompositeLit)
	if !ok {
		return nil
	}

	var values []string
	for _, elt := range compositeLit.Elts {
		if lit, ok := elt.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			value := strings.Trim(lit.Value, `"`)
			if value != "" {
				values = append(values, value)
			}
		}
	}

	return values
}

// resolveLocalConstant finds a constant definition in the current file
func resolveLocalConstant(name string, ctx *parseContext) string {
	for _, decl := range ctx.file.Decls {
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
				if ident.Name == name && i < len(valueSpec.Values) {
					if lit, ok := valueSpec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						return strings.Trim(lit.Value, `"`)
					}
				}
			}
		}
	}

	return ""
}

// resolveImportedConstant finds a constant in an imported package
func resolveImportedConstant(pkgName, constName string, ctx *parseContext) string {
	// find the import path for this package alias
	var importPath string
	for _, imp := range ctx.file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)

		// check if this import has the alias we're looking for
		if imp.Name != nil && imp.Name.Name == pkgName {
			importPath = path
			break
		}

		// check if the package name matches (last component of import path)
		parts := strings.Split(path, "/")
		if len(parts) > 0 && parts[len(parts)-1] == pkgName {
			importPath = path
			break
		}
	}

	if importPath == "" {
		return ""
	}

	// resolve import path to file system path
	pkgDir := resolveImportPath(importPath, ctx.repoRoot)
	if pkgDir == "" {
		return ""
	}

	// parse all .go files in the package directory to find the constant
	return findConstantInPackage(pkgDir, constName)
}

// resolveImportPath converts an import path to a file system path
func resolveImportPath(importPath, repoRoot string) string {
	// for github.com/anchore/syft/... imports, convert to repo-relative path
	if strings.HasPrefix(importPath, "github.com/anchore/syft/") {
		relPath := strings.TrimPrefix(importPath, "github.com/anchore/syft/")
		return filepath.Join(repoRoot, relPath)
	}

	return ""
}

// findConstantInPackage searches for a constant definition in a package directory
func findConstantInPackage(pkgDir, constName string) string {
	files, err := filepath.Glob(filepath.Join(pkgDir, "*.go"))
	if err != nil {
		return ""
	}

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		if value := findConstantInFile(file, constName); value != "" {
			return value
		}
	}

	return ""
}

func findConstantInFile(filePath, constName string) string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		return ""
	}

	for _, decl := range f.Decls {
		if value := searchConstInDecl(decl, constName); value != "" {
			return value
		}
	}

	return ""
}

func searchConstInDecl(decl ast.Decl, constName string) string {
	genDecl, ok := decl.(*ast.GenDecl)
	if !ok || genDecl.Tok != token.CONST {
		return ""
	}

	for _, spec := range genDecl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}

		if value := getConstValue(valueSpec, constName); value != "" {
			return value
		}
	}

	return ""
}

func getConstValue(valueSpec *ast.ValueSpec, constName string) string {
	for i, ident := range valueSpec.Names {
		if ident.Name == constName && i < len(valueSpec.Values) {
			if lit, ok := valueSpec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				return strings.Trim(lit.Value, `"`)
			}
		}
	}
	return ""
}

// extractBinaryClassifiers extracts all binary classifiers with their full information
func extractBinaryClassifiers() []binary.Classifier { //nolint:staticcheck
	classifiers := binary.DefaultClassifiers()

	// return all classifiers (already sorted by the default function)
	return classifiers
}
