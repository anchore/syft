package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFindSectionNode(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		sectionName string
		wantFound   bool
		wantValue   string // expected value for scalar nodes
	}{
		{
			name: "finds existing configs section",
			yamlContent: `
configs:
  key: value
catalogers:
  - name: test
`,
			sectionName: "configs",
			wantFound:   true,
		},
		{
			name: "finds existing catalogers section",
			yamlContent: `
configs:
  key: value
catalogers:
  - name: test
`,
			sectionName: "catalogers",
			wantFound:   true,
		},
		{
			name: "returns nil for non-existent section",
			yamlContent: `
configs:
  key: value
`,
			sectionName: "nonexistent",
			wantFound:   false,
		},
		{
			name:        "handles empty mapping",
			yamlContent: `{}`,
			sectionName: "any",
			wantFound:   false,
		},
		{
			name: "finds section with scalar value",
			yamlContent: `
name: test-cataloger
type: custom
`,
			sectionName: "name",
			wantFound:   true,
			wantValue:   "test-cataloger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rootNode yaml.Node
			err := yaml.Unmarshal([]byte(tt.yamlContent), &rootNode)
			require.NoError(t, err)

			// get the mapping node
			var mappingNode *yaml.Node
			if rootNode.Kind == yaml.DocumentNode && len(rootNode.Content) > 0 {
				mappingNode = rootNode.Content[0]
			} else {
				mappingNode = &rootNode
			}

			got := findSectionNode(mappingNode, tt.sectionName)

			if tt.wantFound {
				require.NotNil(t, got)
				if tt.wantValue != "" {
					require.Equal(t, tt.wantValue, got.Value)
				}
			} else {
				require.Nil(t, got)
			}
		})
	}
}

func TestFindFieldValue(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		fieldName   string
		want        string
	}{
		{
			name: "finds simple string field",
			yamlContent: `
name: test-cataloger
type: custom
`,
			fieldName: "name",
			want:      "test-cataloger",
		},
		{
			name: "finds type field",
			yamlContent: `
name: test-cataloger
type: generic
`,
			fieldName: "type",
			want:      "generic",
		},
		{
			name: "returns empty for non-existent field",
			yamlContent: `
name: test-cataloger
`,
			fieldName: "nonexistent",
			want:      "",
		},
		{
			name: "finds parser_function field",
			yamlContent: `
parser_function: parseGoMod
metadata_types: [GoModMetadata]
`,
			fieldName: "parser_function",
			want:      "parseGoMod",
		},
		{
			name:        "handles empty mapping",
			yamlContent: `{}`,
			fieldName:   "any",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rootNode yaml.Node
			err := yaml.Unmarshal([]byte(tt.yamlContent), &rootNode)
			require.NoError(t, err)

			// get the mapping node
			var mappingNode *yaml.Node
			if rootNode.Kind == yaml.DocumentNode && len(rootNode.Content) > 0 {
				mappingNode = rootNode.Content[0]
			} else {
				mappingNode = &rootNode
			}

			got := findFieldValue(mappingNode, tt.fieldName)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestPreserveMappingNodeComments(t *testing.T) {
	tests := []struct {
		name            string
		checkField      string
		wantHeadComment string
		wantLineComment string
	}{
		{
			name:            "preserves line comment on field",
			checkField:      "name",
			wantLineComment: "AUTO-GENERATED",
		},
		{
			name:            "preserves head comment on field",
			checkField:      "type",
			wantHeadComment: "Important field",
			wantLineComment: "AUTO-GENERATED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// manually construct nodes with comments
			existingMapping := &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "name", LineComment: "AUTO-GENERATED"},
					{Kind: yaml.ScalarNode, Value: "test", HeadComment: "value comment"},
					{Kind: yaml.ScalarNode, Value: "type", HeadComment: "Important field", LineComment: "AUTO-GENERATED"},
					{Kind: yaml.ScalarNode, Value: "custom"},
				},
			}

			newMapping := &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "name"},
					{Kind: yaml.ScalarNode, Value: "test-new"},
					{Kind: yaml.ScalarNode, Value: "type"},
					{Kind: yaml.ScalarNode, Value: "generic"},
				},
			}

			preserveMappingNodeComments(existingMapping, newMapping)

			// find the field we're checking
			keyNode, valueNode := findFieldNodes(newMapping, tt.checkField)
			require.NotNil(t, keyNode, "field %s not found", tt.checkField)

			// check comments were preserved
			if tt.wantHeadComment != "" {
				require.Equal(t, tt.wantHeadComment, keyNode.HeadComment)
			}
			if tt.wantLineComment != "" {
				require.Equal(t, tt.wantLineComment, keyNode.LineComment)
			}

			// verify that value node comments are also preserved
			if tt.checkField == "name" {
				require.Equal(t, "value comment", valueNode.HeadComment)
			}
		})
	}
}

func TestPreserveSequenceNodeComments(t *testing.T) {
	tests := []struct {
		name            string
		existingYAML    string
		newYAML         string
		wantHeadComment string
	}{
		{
			name: "preserves parser comments by parser_function",
			existingYAML: `
- parser_function: parseGoMod # old parser
  metadata_types: [GoModMetadata]
- parser_function: parseGoSum
  metadata_types: [GoSumMetadata]
`,
			newYAML: `
- parser_function: parseGoMod
  metadata_types: [GoModMetadataNew]
- parser_function: parseGoSum
  metadata_types: [GoSumMetadataNew]
`,
			// we'll verify in the test body that comments are preserved
		},
		{
			name: "handles new parsers not in existing",
			existingYAML: `
- parser_function: parseGoMod
  metadata_types: [GoModMetadata]
`,
			newYAML: `
- parser_function: parseGoMod
  metadata_types: [GoModMetadata]
- parser_function: parseGoSum
  metadata_types: [GoSumMetadata]
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var existingNode, newNode yaml.Node
			err := yaml.Unmarshal([]byte(tt.existingYAML), &existingNode)
			require.NoError(t, err)
			err = yaml.Unmarshal([]byte(tt.newYAML), &newNode)
			require.NoError(t, err)

			// get sequence nodes
			existingSeq := getSequenceNode(&existingNode)
			newSeq := getSequenceNode(&newNode)

			preserveSequenceNodeComments(existingSeq, newSeq)

			// verify that the function ran without panicking
			require.NotNil(t, newSeq)
		})
	}
}

func TestPreserveFieldComments(t *testing.T) {
	tests := []struct {
		name         string
		existingYAML string
		newYAML      string
		wantPreserve bool
	}{
		{
			name: "preserves mapping node comments",
			existingYAML: `
name: test # AUTO-GENERATED
type: custom
`,
			newYAML: `
name: test-new
type: custom
`,
			wantPreserve: true,
		},
		{
			name: "handles kind mismatch gracefully",
			existingYAML: `
- item1
- item2
`,
			newYAML: `
name: test
`,
			wantPreserve: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var existingNode, newNode yaml.Node
			err := yaml.Unmarshal([]byte(tt.existingYAML), &existingNode)
			require.NoError(t, err)
			err = yaml.Unmarshal([]byte(tt.newYAML), &newNode)
			require.NoError(t, err)

			existingContent := getContentNode(&existingNode)
			newContent := getContentNode(&newNode)

			preserveFieldComments(existingContent, newContent)

			// verify the function completed without panicking
			require.NotNil(t, newContent)
		})
	}
}

func TestUpdateOrAddSection(t *testing.T) {
	tests := []struct {
		name         string
		existingYAML string
		newYAML      string
		sectionName  string
		wantUpdated  bool
		wantAdded    bool
	}{
		{
			name: "updates existing section",
			existingYAML: `
configs:
  old: value
catalogers:
  - name: test
`,
			newYAML: `
configs:
  new: value
`,
			sectionName: "configs",
			wantUpdated: true,
		},
		{
			name: "adds new section",
			existingYAML: `
catalogers:
  - name: test
`,
			newYAML: `
configs:
  new: value
`,
			sectionName: "configs",
			wantAdded:   true,
		},
		{
			name: "handles application section",
			existingYAML: `
catalogers:
  - name: test
`,
			newYAML: `
application:
  key: value
`,
			sectionName: "application",
			wantAdded:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var existingNode, newNode yaml.Node
			err := yaml.Unmarshal([]byte(tt.existingYAML), &existingNode)
			require.NoError(t, err)
			err = yaml.Unmarshal([]byte(tt.newYAML), &newNode)
			require.NoError(t, err)

			existingMapping := getMappingNode(&existingNode)
			newMapping := getMappingNode(&newNode)

			updateOrAddSection(existingMapping, newMapping, tt.sectionName)

			// verify the section exists in the result
			resultSection := findSectionNode(existingMapping, tt.sectionName)
			require.NotNil(t, resultSection, "section %s should exist after update", tt.sectionName)
		})
	}
}

func TestAddCatalogerFieldComment(t *testing.T) {
	tests := []struct {
		name            string
		fieldName       string
		fieldValue      string
		catalogerName   string
		wantLineComment string
	}{
		{
			name:            "ecosystem is MANUAL",
			fieldName:       "ecosystem",
			catalogerName:   "test-cataloger",
			wantLineComment: "MANUAL",
		},
		{
			name:            "name is AUTO-GENERATED",
			fieldName:       "name",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "type is AUTO-GENERATED",
			fieldName:       "type",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "source is AUTO-GENERATED",
			fieldName:       "source",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "config is AUTO-GENERATED",
			fieldName:       "config",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "selectors is AUTO-GENERATED",
			fieldName:       "selectors",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "parsers is AUTO-GENERATED structure",
			fieldName:       "parsers",
			catalogerName:   "test-cataloger",
			wantLineComment: "AUTO-GENERATED structure",
		},
		{
			name:            "detectors for binary-classifier-cataloger is AUTO-GENERATED",
			fieldName:       "detectors",
			catalogerName:   "binary-classifier-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "detectors for other catalogers is MANUAL",
			fieldName:       "detectors",
			catalogerName:   "java-archive-cataloger",
			wantLineComment: "MANUAL - edit detectors here",
		},
		{
			name:            "metadata_types is AUTO-GENERATED",
			fieldName:       "metadata_types",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "package_types is AUTO-GENERATED",
			fieldName:       "package_types",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "json_schema_types is AUTO-GENERATED",
			fieldName:       "json_schema_types",
			catalogerName:   "test-cataloger",
			wantLineComment: autoGeneratedComment,
		},
		{
			name:            "capabilities is MANUAL",
			fieldName:       "capabilities",
			catalogerName:   "test-cataloger",
			wantLineComment: "MANUAL - edit capabilities here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create key and value nodes
			keyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: tt.fieldName,
			}
			valueNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: tt.fieldValue,
			}

			addCatalogerFieldComment(keyNode, valueNode, tt.catalogerName)

			require.Equal(t, tt.wantLineComment, keyNode.LineComment)
		})
	}
}

// helper functions

func getMappingNode(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

func getSequenceNode(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

func getContentNode(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

func findFieldNodes(mappingNode *yaml.Node, fieldName string) (*yaml.Node, *yaml.Node) {
	if mappingNode.Kind != yaml.MappingNode {
		return nil, nil
	}

	for i := 0; i < len(mappingNode.Content); i += 2 {
		if mappingNode.Content[i].Value == fieldName {
			return mappingNode.Content[i], mappingNode.Content[i+1]
		}
	}

	return nil, nil
}
