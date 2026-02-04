package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities/internal"
)

// TestAppConfigFieldsHaveDescriptions ensures that all application config fields discovered from the
// options package have descriptions, which are required for user-facing documentation.
func TestAppConfigFieldsHaveDescriptions(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := internal.RepoRoot()
	require.NoError(t, err)

	configs, err := DiscoverAppConfigs(repoRoot)
	require.NoError(t, err)

	// verify that all configs have descriptions
	var missingDescriptions []string
	for _, cfg := range configs {
		if cfg.Description == "" {
			missingDescriptions = append(missingDescriptions, cfg.Key)
		}
	}

	require.Empty(t, missingDescriptions, "the following configs are missing descriptions: %v", missingDescriptions)
}

// TestAppConfigKeyFormat validates that all application config keys follow the expected naming convention
// of "ecosystem.field-name" using kebab-case (lowercase with hyphens, no underscores or spaces).
func TestAppConfigKeyFormat(t *testing.T) {
	checkCompletenessTestsEnabled(t)

	repoRoot, err := internal.RepoRoot()
	require.NoError(t, err)

	configs, err := DiscoverAppConfigs(repoRoot)
	require.NoError(t, err)

	// verify that all config keys follow the expected format
	for _, cfg := range configs {
		// keys should be in format "ecosystem.field-name" or "ecosystem.nested.field-name"
		require.Contains(t, cfg.Key, ".", "config key should contain at least one dot: %s", cfg.Key)

		// keys should use kebab-case (all lowercase with hyphens)
		require.NotContains(t, cfg.Key, "_", "config key should not contain underscores: %s", cfg.Key)
		require.NotContains(t, cfg.Key, " ", "config key should not contain spaces: %s", cfg.Key)
	}
}

func TestCleanDescription(t *testing.T) {
	tests := []struct {
		name string
		desc string
		want string
	}{
		{
			name: "single line no extra whitespace",
			desc: "this is a description",
			want: "this is a description",
		},
		{
			name: "multiple spaces collapsed",
			desc: "this  has   multiple    spaces",
			want: "this has multiple spaces",
		},
		{
			name: "multi-line description",
			desc: "this is a\nmulti-line\ndescription",
			want: "this is a multi-line description",
		},
		{
			name: "leading and trailing whitespace",
			desc: "  \t  description with spaces  \t  ",
			want: "description with spaces",
		},
		{
			name: "tabs and newlines",
			desc: "description\t\twith\n\ttabs",
			want: "description with tabs",
		},
		{
			name: "empty string",
			desc: "",
			want: "",
		},
		{
			name: "only whitespace",
			desc: "   \n\t  ",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanDescription(tt.desc)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractYAMLTag(t *testing.T) {
	tests := []struct {
		name   string
		tagStr string
		want   string
	}{
		{
			name:   "simple yaml tag",
			tagStr: "`yaml:\"field-name\"`",
			want:   "field-name",
		},
		{
			name:   "yaml tag with omitempty",
			tagStr: "`yaml:\"field-name,omitempty\"`",
			want:   "field-name",
		},
		{
			name:   "yaml tag with multiple options",
			tagStr: "`yaml:\"field-name,omitempty,inline\"`",
			want:   "field-name",
		},
		{
			name:   "yaml tag dash means skip",
			tagStr: "`yaml:\"-\"`",
			want:   "-",
		},
		{
			name:   "no yaml tag",
			tagStr: "`json:\"field-name\"`",
			want:   "",
		},
		{
			name:   "empty tag",
			tagStr: "",
			want:   "",
		},
		{
			name:   "yaml tag with json tag",
			tagStr: "`yaml:\"yaml-name\" json:\"json-name\"`",
			want:   "yaml-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// construct a minimal ast.Field with the tag
			field := &ast.Field{}
			if tt.tagStr != "" {
				field.Tag = &ast.BasicLit{
					Kind:  token.STRING,
					Value: tt.tagStr,
				}
			}

			got := extractYAMLTag(field)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsNestedStruct(t *testing.T) {
	tests := []struct {
		name string
		expr ast.Expr
		want bool
	}{
		{
			name: "custom struct type",
			expr: &ast.Ident{Name: "MainModuleVersion"},
			want: true,
		},
		{
			name: "string type",
			expr: &ast.Ident{Name: "string"},
			want: false,
		},
		{
			name: "int type",
			expr: &ast.Ident{Name: "int"},
			want: false,
		},
		{
			name: "bool type",
			expr: &ast.Ident{Name: "bool"},
			want: false,
		},
		{
			name: "pointer type",
			expr: &ast.StarExpr{X: &ast.Ident{Name: "Config"}},
			want: false,
		},
		{
			name: "array type",
			expr: &ast.ArrayType{Elt: &ast.Ident{Name: "string"}},
			want: false,
		},
		{
			name: "map type",
			expr: &ast.MapType{
				Key:   &ast.Ident{Name: "string"},
				Value: &ast.Ident{Name: "string"},
			},
			want: false,
		},
		{
			name: "int32 type",
			expr: &ast.Ident{Name: "int32"},
			want: false,
		},
		{
			name: "uint64 type",
			expr: &ast.Ident{Name: "uint64"},
			want: false,
		},
		{
			name: "float64 type",
			expr: &ast.Ident{Name: "float64"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNestedStruct(tt.expr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractStringLiteral(t *testing.T) {
	tests := []struct {
		name string
		expr ast.Expr
		want string
	}{
		{
			name: "double quoted string",
			expr: &ast.BasicLit{
				Kind:  token.STRING,
				Value: `"hello world"`,
			},
			want: "hello world",
		},
		{
			name: "backtick string",
			expr: &ast.BasicLit{
				Kind:  token.STRING,
				Value: "`hello world`",
			},
			want: "hello world",
		},
		{
			name: "empty string",
			expr: &ast.BasicLit{
				Kind:  token.STRING,
				Value: `""`,
			},
			want: "",
		},
		{
			name: "string with spaces",
			expr: &ast.BasicLit{
				Kind:  token.STRING,
				Value: `"  spaces  "`,
			},
			want: "  spaces  ",
		},
		{
			name: "not a string literal (int)",
			expr: &ast.BasicLit{
				Kind:  token.INT,
				Value: "42",
			},
			want: "",
		},
		{
			name: "not a basic lit",
			expr: &ast.Ident{Name: "someVar"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStringLiteral(tt.expr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractFieldPathFromRef(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "simple field reference",
			src:  "&o.Field",
			want: "Field",
		},
		{
			name: "nested field reference",
			src:  "&o.Parent.Field",
			want: "Parent.Field",
		},
		{
			name: "deeply nested field reference",
			src:  "&o.MainModuleVersion.FromLDFlags",
			want: "MainModuleVersion.FromLDFlags",
		},
		{
			name: "three levels deep",
			src:  "&o.Level1.Level2.Level3",
			want: "Level1.Level2.Level3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// parse the expression
			expr, err := parser.ParseExpr(tt.src)
			require.NoError(t, err)

			got := extractFieldPathFromRef(expr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractAppValue(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want interface{}
	}{
		{
			name: "string literal",
			src:  `"hello"`,
			want: "hello",
		},
		{
			name: "int literal",
			src:  "42",
			want: "42",
		},
		{
			name: "float literal",
			src:  "3.14",
			want: "3.14",
		},
		{
			name: "bool true",
			src:  "true",
			want: true,
		},
		{
			name: "bool false",
			src:  "false",
			want: false,
		},
		{
			name: "nil value",
			src:  "nil",
			want: nil,
		},
		{
			name: "empty string",
			src:  `""`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// parse the expression
			expr, err := parser.ParseExpr(tt.src)
			require.NoError(t, err)

			got := extractAppValue(expr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestExtractAppValue_NestedStruct(t *testing.T) {
	// test nested struct separately since it returns a map
	src := `struct{Field1 string; Field2 bool}{Field1: "value", Field2: true}`

	// parse as a composite literal
	expr, err := parser.ParseExpr(src)
	require.NoError(t, err)

	// extract the composite literal
	compositeLit, ok := expr.(*ast.CompositeLit)
	require.True(t, ok)

	got := extractAppValue(compositeLit)

	// verify it's a map with the expected values
	gotMap, ok := got.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "value", gotMap["Field1"])
	require.Equal(t, true, gotMap["Field2"])
}
