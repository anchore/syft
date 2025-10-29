package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReturnsPackageCataloger(t *testing.T) {
	tests := []struct {
		name string
		code string
		want bool
	}{
		{
			name: "returns pkg.Cataloger",
			code: `func NewFoo() pkg.Cataloger { return nil }`,
			want: true,
		},
		{
			name: "returns bare Cataloger",
			code: `func NewFoo() Cataloger { return nil }`,
			want: true,
		},
		{
			name: "returns multiple values",
			code: `func NewFoo() (pkg.Cataloger, error) { return nil, nil }`,
			want: false,
		},
		{
			name: "returns error",
			code: `func NewFoo() error { return nil }`,
			want: false,
		},
		{
			name: "returns pointer to Cataloger",
			code: `func NewFoo() *pkg.Cataloger { return nil }`,
			want: false,
		},
		{
			name: "returns string",
			code: `func NewFoo() string { return "" }`,
			want: false,
		},
		{
			name: "no return type",
			code: `func NewFoo() { }`,
			want: false,
		},
		{
			name: "returns wrong package Cataloger",
			code: `func NewFoo() other.Cataloger { return nil }`,
			want: false,
		},
		{
			name: "returns pkg.OtherType",
			code: `func NewFoo() pkg.OtherType { return nil }`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			funcDecl := parseFuncDecl(t, tt.code)
			got := returnsPackageCataloger(funcDecl)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsGenericNewCatalogerCall(t *testing.T) {
	tests := []struct {
		name string
		code string
		want bool
	}{
		{
			name: "generic.NewCataloger call",
			code: `generic.NewCataloger("foo")`,
			want: true,
		},
		{
			name: "generic.NewCataloger with no args",
			code: `generic.NewCataloger()`,
			want: true,
		},
		{
			name: "other.NewCataloger call",
			code: `other.NewCataloger("foo")`,
			want: false,
		},
		{
			name: "generic.OtherMethod call",
			code: `generic.OtherMethod("foo")`,
			want: false,
		},
		{
			name: "bare NewCataloger call",
			code: `NewCataloger("foo")`,
			want: false,
		},
		{
			name: "nested call",
			code: `foo(generic.NewCataloger("bar"))`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callExpr := parseCallExpr(t, tt.code)
			got := isGenericNewCatalogerCall(callExpr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractStringSliceFromExpr(t *testing.T) {
	tests := []struct {
		name string
		code string
		want []string
	}{
		{
			name: "strset.New with strings",
			code: `strset.New([]string{"foo", "bar", "baz"})`,
			want: []string{"foo", "bar", "baz"},
		},
		{
			name: "strset.New with single string",
			code: `strset.New([]string{"single"})`,
			want: []string{"single"},
		},
		{
			name: "strset.New with empty slice",
			code: `strset.New([]string{})`,
			want: nil,
		},
		{
			name: "other.New with strings",
			code: `other.New([]string{"x", "y"})`,
			want: []string{"x", "y"},
		},
		{
			name: "call with no args",
			code: `strset.New()`,
			want: nil,
		},
		{
			name: "call with non-composite-literal arg",
			code: `strset.New("not a slice")`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callExpr := parseCallExpr(t, tt.code)
			got := extractStringSliceFromExpr(callExpr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSearchConstInDecl(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		constName string
		want      string
	}{
		{
			name:      "single const",
			code:      `const Foo = "bar"`,
			constName: "Foo",
			want:      "bar",
		},
		{
			name: "grouped consts - first",
			code: `const (
				Foo = "bar"
				Baz = "qux"
			)`,
			constName: "Foo",
			want:      "bar",
		},
		{
			name: "grouped consts - second",
			code: `const (
				Foo = "bar"
				Baz = "qux"
			)`,
			constName: "Baz",
			want:      "qux",
		},
		{
			name:      "const not found",
			code:      `const Foo = "bar"`,
			constName: "Missing",
			want:      "",
		},
		{
			name:      "var declaration instead of const",
			code:      `var Foo = "bar"`,
			constName: "Foo",
			want:      "",
		},
		{
			name:      "const with non-string value",
			code:      `const Foo = 42`,
			constName: "Foo",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genDecl := parseConstDecl(t, tt.code)
			got := searchConstInDecl(genDecl, tt.constName)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetConstValue(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		constName string
		want      string
	}{
		{
			name:      "single const match",
			code:      `const Foo = "bar"`,
			constName: "Foo",
			want:      "bar",
		},
		{
			name:      "no match",
			code:      `const Foo = "bar"`,
			constName: "NotFoo",
			want:      "",
		},
		{
			name:      "non-string literal",
			code:      `const Foo = 123`,
			constName: "Foo",
			want:      "",
		},
		{
			name:      "const with complex value",
			code:      `const Foo = Bar + "suffix"`,
			constName: "Foo",
			want:      "",
		},
		{
			name:      "first of multiple in same spec",
			code:      `const Foo, Bar = "baz", "qux"`,
			constName: "Foo",
			want:      "baz",
		},
		{
			name:      "second of multiple in same spec",
			code:      `const Foo, Bar = "baz", "qux"`,
			constName: "Bar",
			want:      "qux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genDecl := parseConstDecl(t, tt.code)
			require.Equal(t, token.CONST, genDecl.Tok)
			require.NotEmpty(t, genDecl.Specs)

			// getConstValue works on a single ValueSpec, so we need to find the right one
			// in case of grouped constants, each const is its own spec
			var got string
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				require.True(t, ok)

				got = getConstValue(valueSpec, tt.constName)
				if got != "" {
					break
				}
			}

			require.Equal(t, tt.want, got)
		})
	}
}

func TestResolveImportPath(t *testing.T) {
	const testRepoRoot = "/repo/root"

	tests := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "syft pkg cataloger golang",
			importPath: "github.com/anchore/syft/syft/pkg/cataloger/golang",
			want:       "/repo/root/syft/pkg/cataloger/golang",
		},
		{
			name:       "syft internal capabilities",
			importPath: "github.com/anchore/syft/internal/capabilities",
			want:       "/repo/root/internal/capabilities",
		},
		{
			name:       "syft root package",
			importPath: "github.com/anchore/syft/syft",
			want:       "/repo/root/syft",
		},
		{
			name:       "external package",
			importPath: "github.com/other/repo/pkg",
			want:       "",
		},
		{
			name:       "standard library",
			importPath: "fmt",
			want:       "",
		},
		{
			name:       "empty import path",
			importPath: "",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveImportPath(tt.importPath, testRepoRoot)
			require.Equal(t, tt.want, got)
		})
	}
}

// test helper functions

// parseFuncDecl parses a function declaration from a code string
func parseFuncDecl(t *testing.T, code string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", "package test\n"+code, 0)
	require.NoError(t, err)
	require.Len(t, file.Decls, 1, "expected exactly one declaration")
	funcDecl, ok := file.Decls[0].(*ast.FuncDecl)
	require.True(t, ok, "expected declaration to be a function")
	return funcDecl
}

// parseCallExpr parses a call expression from a code string
func parseCallExpr(t *testing.T, code string) *ast.CallExpr {
	t.Helper()
	expr, err := parser.ParseExpr(code)
	require.NoError(t, err)
	callExpr, ok := expr.(*ast.CallExpr)
	require.True(t, ok, "expected expression to be a call expression")
	return callExpr
}

// parseCompositeLit parses a composite literal from a code string
func parseCompositeLit(t *testing.T, code string) *ast.CompositeLit {
	t.Helper()
	expr, err := parser.ParseExpr(code)
	require.NoError(t, err)
	lit, ok := expr.(*ast.CompositeLit)
	require.True(t, ok, "expected expression to be a composite literal")
	return lit
}

// parseConstDecl parses a const declaration from a code string and returns the GenDecl
func parseConstDecl(t *testing.T, code string) *ast.GenDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", "package test\n"+code, 0)
	require.NoError(t, err)
	require.Len(t, file.Decls, 1, "expected exactly one declaration")
	genDecl, ok := file.Decls[0].(*ast.GenDecl)
	require.True(t, ok, "expected declaration to be a general declaration")
	return genDecl
}
