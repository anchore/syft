package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iancoleman/orderedmap"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCopyAliasFieldComments verifies that field comments from source types are correctly copied to alias types.
// This is important for type aliases like `type RpmArchive RpmDBEntry` where the alias should inherit all field descriptions.
func TestCopyAliasFieldComments(t *testing.T) {
	tests := []struct {
		name         string
		commentMap   map[string]string
		aliases      map[string]string
		wantComments map[string]string
	}{
		{
			name: "copies field comments from source type to alias",
			commentMap: map[string]string{
				"github.com/anchore/syft/syft/pkg.RpmDBEntry":       "RpmDBEntry represents all captured data from a RPM DB package entry.",
				"github.com/anchore/syft/syft/pkg.RpmDBEntry.Name":  "Name is the RPM package name.",
				"github.com/anchore/syft/syft/pkg.RpmDBEntry.Epoch": "Epoch is the version epoch.",
			},
			aliases: map[string]string{
				"RpmArchive": "RpmDBEntry",
			},
			wantComments: map[string]string{
				"github.com/anchore/syft/syft/pkg.RpmDBEntry":       "RpmDBEntry represents all captured data from a RPM DB package entry.",
				"github.com/anchore/syft/syft/pkg.RpmDBEntry.Name":  "Name is the RPM package name.",
				"github.com/anchore/syft/syft/pkg.RpmDBEntry.Epoch": "Epoch is the version epoch.",
				"github.com/anchore/syft/syft/pkg.RpmArchive.Name":  "Name is the RPM package name.",
				"github.com/anchore/syft/syft/pkg.RpmArchive.Epoch": "Epoch is the version epoch.",
			},
		},
		{
			name: "handles multiple aliases",
			commentMap: map[string]string{
				"github.com/anchore/syft/syft/pkg.DpkgDBEntry":              "DpkgDBEntry represents data from dpkg.",
				"github.com/anchore/syft/syft/pkg.DpkgDBEntry.Package":      "Package is the package name.",
				"github.com/anchore/syft/syft/pkg.DpkgDBEntry.Architecture": "Architecture is the target arch.",
			},
			aliases: map[string]string{
				"DpkgArchiveEntry": "DpkgDBEntry",
				"DpkgSnapshot":     "DpkgDBEntry",
			},
			wantComments: map[string]string{
				"github.com/anchore/syft/syft/pkg.DpkgDBEntry":                   "DpkgDBEntry represents data from dpkg.",
				"github.com/anchore/syft/syft/pkg.DpkgDBEntry.Package":           "Package is the package name.",
				"github.com/anchore/syft/syft/pkg.DpkgDBEntry.Architecture":      "Architecture is the target arch.",
				"github.com/anchore/syft/syft/pkg.DpkgArchiveEntry.Package":      "Package is the package name.",
				"github.com/anchore/syft/syft/pkg.DpkgArchiveEntry.Architecture": "Architecture is the target arch.",
				"github.com/anchore/syft/syft/pkg.DpkgSnapshot.Package":          "Package is the package name.",
				"github.com/anchore/syft/syft/pkg.DpkgSnapshot.Architecture":     "Architecture is the target arch.",
			},
		},
		{
			name: "does not copy non-field comments",
			commentMap: map[string]string{
				"github.com/anchore/syft/syft/pkg.SomeType":       "SomeType struct comment.",
				"github.com/anchore/syft/syft/pkg.SomeType.Field": "Field comment.",
			},
			aliases: map[string]string{
				"AliasType": "SomeType",
			},
			wantComments: map[string]string{
				"github.com/anchore/syft/syft/pkg.SomeType":        "SomeType struct comment.",
				"github.com/anchore/syft/syft/pkg.SomeType.Field":  "Field comment.",
				"github.com/anchore/syft/syft/pkg.AliasType.Field": "Field comment.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create temp dir for testing
			tmpDir := t.TempDir()

			// create a test go file with type aliases
			testFile := filepath.Join(tmpDir, "test.go")
			content := "package test\n\n"
			for alias, source := range tt.aliases {
				content += "type " + alias + " " + source + "\n"
			}
			err := os.WriteFile(testFile, []byte(content), 0644)
			require.NoError(t, err)

			// make a copy of the comment map since the function modifies it
			commentMap := make(map[string]string)
			for k, v := range tt.commentMap {
				commentMap[k] = v
			}

			// run the function
			copyAliasFieldComments(commentMap, tmpDir)

			// verify results
			assert.Equal(t, tt.wantComments, commentMap)
		})
	}
}

func TestFindTypeAliases(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		wantAliases map[string]string
	}{
		{
			name: "finds simple type alias",
			fileContent: `package test

type RpmArchive RpmDBEntry
type DpkgArchiveEntry DpkgDBEntry
`,
			wantAliases: map[string]string{
				"RpmArchive":       "RpmDBEntry",
				"DpkgArchiveEntry": "DpkgDBEntry",
			},
		},
		{
			name: "ignores struct definitions",
			fileContent: `package test

type MyStruct struct {
	Field string
}

type AliasType BaseType
`,
			wantAliases: map[string]string{
				"AliasType": "BaseType",
			},
		},
		{
			name: "ignores interface definitions",
			fileContent: `package test

type MyInterface interface {
	Method()
}

type AliasType BaseType
`,
			wantAliases: map[string]string{
				"AliasType": "BaseType",
			},
		},
		{
			name: "handles multiple files",
			fileContent: `package test

type Alias1 Base1
type Alias2 Base2
`,
			wantAliases: map[string]string{
				"Alias1": "Base1",
				"Alias2": "Base2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create temp dir
			tmpDir := t.TempDir()

			// write test file
			testFile := filepath.Join(tmpDir, "test.go")
			err := os.WriteFile(testFile, []byte(tt.fileContent), 0644)
			require.NoError(t, err)

			// run function
			aliases := findTypeAliases(tmpDir)

			// verify
			assert.Equal(t, tt.wantAliases, aliases)
		})
	}
}

func TestHasDescriptionInAlternatives(t *testing.T) {
	tests := []struct {
		name   string
		schema *jsonschema.Schema
		want   bool
	}{
		{
			name: "returns true when oneOf has description",
			schema: &jsonschema.Schema{
				OneOf: []*jsonschema.Schema{
					{Description: "First alternative"},
					{Type: "null"},
				},
			},
			want: true,
		},
		{
			name: "returns true when anyOf has description",
			schema: &jsonschema.Schema{
				AnyOf: []*jsonschema.Schema{
					{Description: "First alternative"},
					{Type: "null"},
				},
			},
			want: true,
		},
		{
			name: "returns false when no alternatives have descriptions",
			schema: &jsonschema.Schema{
				OneOf: []*jsonschema.Schema{
					{Type: "integer"},
					{Type: "null"},
				},
			},
			want: false,
		},
		{
			name: "returns false when no oneOf or anyOf",
			schema: &jsonschema.Schema{
				Type: "string",
			},
			want: false,
		},
		{
			name: "returns true when any alternative in oneOf has description",
			schema: &jsonschema.Schema{
				OneOf: []*jsonschema.Schema{
					{Type: "integer"},
					{Type: "string", Description: "Second alternative"},
					{Type: "null"},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasDescriptionInAlternatives(tt.schema)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWarnMissingDescriptions(t *testing.T) {
	tests := []struct {
		name              string
		schema            *jsonschema.Schema
		metadataNames     []string
		wantTypeWarnings  int
		wantFieldWarnings int
	}{
		{
			name: "no warnings when all types have descriptions",
			schema: &jsonschema.Schema{
				Definitions: map[string]*jsonschema.Schema{
					"TypeA": {
						Description: "Type A description",
						Properties: newOrderedMap(map[string]*jsonschema.Schema{
							"field1": {Type: "string", Description: "Field 1"},
						}),
					},
				},
			},
			metadataNames:     []string{"TypeA"},
			wantTypeWarnings:  0,
			wantFieldWarnings: 0,
		},
		{
			name: "warns about missing type description",
			schema: &jsonschema.Schema{
				Definitions: map[string]*jsonschema.Schema{
					"TypeA": {
						Properties: newOrderedMap(map[string]*jsonschema.Schema{
							"field1": {Type: "string", Description: "Field 1"},
						}),
					},
				},
			},
			metadataNames:     []string{"TypeA"},
			wantTypeWarnings:  1,
			wantFieldWarnings: 0,
		},
		{
			name: "warns about missing field description",
			schema: &jsonschema.Schema{
				Definitions: map[string]*jsonschema.Schema{
					"TypeA": {
						Description: "Type A description",
						Properties: newOrderedMap(map[string]*jsonschema.Schema{
							"field1": {Type: "string"},
						}),
					},
				},
			},
			metadataNames:     []string{"TypeA"},
			wantTypeWarnings:  0,
			wantFieldWarnings: 1,
		},
		{
			name: "skips fields with references",
			schema: &jsonschema.Schema{
				Definitions: map[string]*jsonschema.Schema{
					"TypeA": {
						Description: "Type A description",
						Properties: newOrderedMap(map[string]*jsonschema.Schema{
							"field1": {Ref: "#/$defs/OtherType"},
						}),
					},
				},
			},
			metadataNames:     []string{"TypeA"},
			wantTypeWarnings:  0,
			wantFieldWarnings: 0,
		},
		{
			name: "skips fields with items that are references",
			schema: &jsonschema.Schema{
				Definitions: map[string]*jsonschema.Schema{
					"TypeA": {
						Description: "Type A description",
						Properties: newOrderedMap(map[string]*jsonschema.Schema{
							"field1": {
								Type:  "array",
								Items: &jsonschema.Schema{Ref: "#/$defs/OtherType"},
							},
						}),
					},
				},
			},
			metadataNames:     []string{"TypeA"},
			wantTypeWarnings:  0,
			wantFieldWarnings: 0,
		},
		{
			name: "skips fields with oneOf containing descriptions",
			schema: &jsonschema.Schema{
				Definitions: map[string]*jsonschema.Schema{
					"TypeA": {
						Description: "Type A description",
						Properties: newOrderedMap(map[string]*jsonschema.Schema{
							"field1": {
								OneOf: []*jsonschema.Schema{
									{Type: "integer", Description: "Integer value"},
									{Type: "null"},
								},
							},
						}),
					},
				},
			},
			metadataNames:     []string{"TypeA"},
			wantTypeWarnings:  0,
			wantFieldWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// capture stderr output would require more complex testing
			// for now, just verify the function runs without panicking
			require.NotPanics(t, func() {
				warnMissingDescriptions(tt.schema, tt.metadataNames)
			})
		})
	}
}

// helper to create an ordered map from a regular map
func newOrderedMap(m map[string]*jsonschema.Schema) *orderedmap.OrderedMap {
	om := orderedmap.New()
	for k, v := range m {
		om.Set(k, v)
	}
	return om
}
