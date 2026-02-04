// this file links catalogers to their configuration structs by analyzing constructor function signatures to determine which config struct each cataloger uses.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// LinkCatalogersToConfigs analyzes cataloger constructor functions to determine which config struct
// each cataloger uses. Returns a map where key is the cataloger name (e.g., "go-module-binary-cataloger")
// and value is the config struct reference (e.g., "golang.CatalogerConfig").
// Returns empty string for catalogers that don't take a config parameter.
func LinkCatalogersToConfigs(repoRoot string) (map[string]string, error) {
	catalogerRoot := filepath.Join(repoRoot, "syft", "pkg", "cataloger")
	return LinkCatalogersToConfigsFromPath(catalogerRoot, repoRoot)
}

// LinkCatalogersToConfigsFromPath analyzes cataloger constructor functions in the specified directory
// to determine which config struct each cataloger uses. This is the parameterized version that allows
// testing with custom fixture directories.
// Returns a map where key is the cataloger name (e.g., "go-module-binary-cataloger")
// and value is the config struct reference (e.g., "golang.CatalogerConfig").
// Returns empty string for catalogers that don't take a config parameter.
// The baseRoot parameter is used for relative path calculation to determine package names.
func LinkCatalogersToConfigsFromPath(catalogerRoot, baseRoot string) (map[string]string, error) {
	// find all .go files under the cataloger root recursively
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

	linkages := make(map[string]string)

	for _, file := range files {
		links, err := linkCatalogersInFile(file, baseRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}

		for catalogerName, configType := range links {
			if existing, ok := linkages[catalogerName]; ok && existing != configType {
				return nil, fmt.Errorf("conflicting config types for cataloger %q: %s vs %s", catalogerName, existing, configType)
			}
			linkages[catalogerName] = configType
		}
	}

	return linkages, nil
}

func linkCatalogersInFile(path, repoRoot string) (map[string]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	// extract package name from file path
	relPath, err := filepath.Rel(repoRoot, path)
	if err != nil {
		relPath = path
	}
	packageName := extractPackageNameFromPath(relPath)
	if packageName == "" {
		return nil, nil
	}

	linkages := make(map[string]string)

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

		// extract the cataloger name from the function body
		catalogerName := extractCatalogerName(funcDecl, f, path, repoRoot)
		if catalogerName == "" {
			// couldn't determine cataloger name, skip
			continue
		}

		// extract config type from function parameters
		configType := extractConfigParameter(funcDecl, packageName)

		// store the linkage (empty string means no config)
		linkages[catalogerName] = configType
	}

	return linkages, nil
}

// extractCatalogerName extracts the cataloger name from the function body.
// It looks for:
// 1. generic.NewCataloger("name") calls
// 2. Cataloger implementations that define Name() method
// 3. Hardcoded name constants
func extractCatalogerName(funcDecl *ast.FuncDecl, file *ast.File, filePath, repoRoot string) string {
	if funcDecl.Body == nil {
		return ""
	}

	ctx := &parseContext{
		file:     file,
		filePath: filePath,
		repoRoot: repoRoot,
	}

	var catalogerName string

	// walk the function body to find generic.NewCataloger call or name assignment
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
					return false // found it, stop searching
				}
				// handle constant identifiers
				if ident, ok := callExpr.Args[0].(*ast.Ident); ok {
					catalogerName = resolveLocalConstant(ident.Name, ctx)
					return false // found it, stop searching
				}
			}
		}

		return true
	})

	// if we didn't find a generic.NewCataloger call, try to infer from custom cataloger
	if catalogerName == "" {
		catalogerName = inferCatalogerNameFromCustomImpl(funcDecl, file, ctx)
	}

	return catalogerName
}

// inferCatalogerNameFromCustomImpl tries to infer the cataloger name from custom cataloger implementations
// by looking for Name() method implementations or hardcoded name variables
func inferCatalogerNameFromCustomImpl(funcDecl *ast.FuncDecl, file *ast.File, ctx *parseContext) string {
	typeName := extractReturnTypeName(funcDecl)
	if typeName == "" {
		return ""
	}
	return findNameMethodReturn(file, typeName, ctx)
}

// extractReturnTypeName extracts the type name from the return statement of a constructor function
func extractReturnTypeName(funcDecl *ast.FuncDecl) string {
	var typeName string

	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		returnStmt, ok := n.(*ast.ReturnStmt)
		if !ok || len(returnStmt.Results) == 0 {
			return true
		}

		result := returnStmt.Results[0]

		// handle &Type{...}
		if unaryExpr, ok := result.(*ast.UnaryExpr); ok && unaryExpr.Op == token.AND {
			if compLit, ok := unaryExpr.X.(*ast.CompositeLit); ok {
				if ident, ok := compLit.Type.(*ast.Ident); ok {
					typeName = ident.Name
					return false
				}
			}
		}

		// handle Type{...}
		if compLit, ok := result.(*ast.CompositeLit); ok {
			if ident, ok := compLit.Type.(*ast.Ident); ok {
				typeName = ident.Name
				return false
			}
		}

		return true
	})

	return typeName
}

// findNameMethodReturn finds the Name() method for the given type and extracts its return value
func findNameMethodReturn(file *ast.File, typeName string, ctx *parseContext) string {
	for _, decl := range file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Name.Name != "Name" {
			continue
		}

		if funcDecl.Recv == nil || len(funcDecl.Recv.List) == 0 {
			continue
		}

		recvTypeName := extractReceiverTypeName(funcDecl.Recv.List[0].Type)
		if recvTypeName != typeName {
			continue
		}

		// found the Name() method, extract the return value
		if funcDecl.Body != nil {
			if name := extractNameFromMethodBody(funcDecl.Body, ctx); name != "" {
				return name
			}
		}
	}

	return ""
}

// extractReceiverTypeName extracts the type name from a receiver type expression
func extractReceiverTypeName(recvType ast.Expr) string {
	// handle both T and *T receivers
	if ident, ok := recvType.(*ast.Ident); ok {
		return ident.Name
	}
	if starExpr, ok := recvType.(*ast.StarExpr); ok {
		if ident, ok := starExpr.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

// extractNameFromMethodBody extracts the cataloger name from a Name() method body
func extractNameFromMethodBody(body *ast.BlockStmt, ctx *parseContext) string {
	var name string
	ast.Inspect(body, func(n ast.Node) bool {
		returnStmt, ok := n.(*ast.ReturnStmt)
		if !ok || len(returnStmt.Results) == 0 {
			return true
		}

		// handle string literal
		if lit, ok := returnStmt.Results[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			name = strings.Trim(lit.Value, `"`)
			return false
		}

		// handle constant identifier (e.g., pomCatalogerName)
		if ident, ok := returnStmt.Results[0].(*ast.Ident); ok {
			name = resolveLocalConstant(ident.Name, ctx)
			return false
		}

		return true
	})
	return name
}

// extractConfigParameter extracts the config type from the first parameter of a cataloger constructor.
// Returns empty string if no config parameter is found.
// Returns format: "packageName.StructName" (e.g., "golang.CatalogerConfig")
func extractConfigParameter(funcDecl *ast.FuncDecl, localPackageName string) string {
	if funcDecl.Type.Params == nil || len(funcDecl.Type.Params.List) == 0 {
		// no parameters, no config
		return ""
	}

	// check the first parameter
	firstParam := funcDecl.Type.Params.List[0]
	if firstParam.Type == nil {
		return ""
	}

	// extract the type name
	configType := extractConfigTypeName(firstParam.Type, localPackageName)

	// filter out non-config types
	if configType != "" && !looksLikeConfigType(configType) {
		return ""
	}

	return configType
}

// extractConfigTypeName extracts the full type name from a parameter type expression
func extractConfigTypeName(typeExpr ast.Expr, localPackageName string) string {
	switch t := typeExpr.(type) {
	case *ast.Ident:
		// local type (e.g., CatalogerConfig)
		return localPackageName + "." + t.Name
	case *ast.SelectorExpr:
		// imported type (e.g., java.ArchiveCatalogerConfig)
		if pkgIdent, ok := t.X.(*ast.Ident); ok {
			return pkgIdent.Name + "." + t.Sel.Name
		}
	}
	return ""
}

// looksLikeConfigType checks if a type name looks like a configuration struct
func looksLikeConfigType(typeName string) bool {
	// remove package prefix
	parts := strings.Split(typeName, ".")
	if len(parts) < 2 {
		return false
	}

	structName := parts[len(parts)-1]

	// check for common config patterns
	return strings.Contains(structName, "Config")
}
