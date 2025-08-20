package modelartifact

import (
	"context"
	"io"
	"strings"
	"testing"

	anchorefile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigJSON(t *testing.T) {
	tests := []struct {
		name          string
		configContent string
		expectedName  string
		expectedType  string
		shouldDetect  bool
	}{
		// {
		// 	name: "valid model config with _name_or_path",
		// 	configContent: `{
		// 		"name_or_path": "microsoft/DialoGPT-medium",
		// 		"model_type": "gpt2",
		// 		"architectures": ["GPT2LMHeadModel"]
		// 	}`,
		// 	expectedName: "microsoft/DialoGPT-medium",
		// 	expectedType: "gpt2",
		// 	shouldDetect: true,
		// },
		{
			name: "valid model config with model_type only",
			configContent: `{
				"model_type": "bert",
				"hidden_size": 768
			}`,
			expectedName: "test",
			expectedType: "bert",
			shouldDetect: true,
		},
		{
			name: "valid model config with architectures only",
			configContent: `{
				"architectures": ["BertForSequenceClassification"],
				"num_labels": 2
			}`,
			expectedName: "test",
			expectedType: "",
			shouldDetect: true,
		},
		{
			name: "invalid config - no model indicators",
			configContent: `{
				"some_other_field": "value",
				"version": "1.0"
			}`,
			shouldDetect: false,
		},
		{
			name: "invalid JSON",
			configContent: `{
				"invalid": json
			}`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := file.LocationReadCloser{
				Location: file.NewLocationFromDirectory("/test/config.json", anchorefile.Reference{
					RealPath: "/test/config.json",
				}),
				ReadCloser: io.NopCloser(strings.NewReader(tt.configContent)),
			}

			packages, relationships, err := parseConfigJSON(context.Background(), nil, &generic.Environment{}, reader)

			if !tt.shouldDetect {
				assert.Empty(t, packages)
				assert.Empty(t, relationships)
				return
			}

			require.NoError(t, err)
			require.Len(t, packages, 1)
			assert.Empty(t, relationships)

			pack := packages[0]
			assert.Equal(t, tt.expectedName, pack.Name)
			assert.Equal(t, pkg.ModelArtifactPkg, pack.Type)
			assert.Equal(t, "UNKNOWN", pack.Version) // Local model version
			assert.NotEmpty(t, pack.PURL)            // Should have a PURL

			metadata, ok := pack.Metadata.(pkg.ModelArtifact)
			require.True(t, ok)
			assert.Equal(t, tt.expectedType, metadata.ModelType)
		})
	}
}

func TestIsModelConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]interface{}
		expected bool
	}{
		{
			name: "has name_or_path",
			config: map[string]interface{}{
				"name_or_path": "some/model",
			},
			expected: true,
		},
		{
			name: "has model_type",
			config: map[string]interface{}{
				"model_type": "bert",
			},
			expected: true,
		},
		{
			name: "has architectures",
			config: map[string]interface{}{
				"architectures": []string{"BertModel"},
			},
			expected: true,
		},
		{
			name: "no model indicators",
			config: map[string]interface{}{
				"some_field": "value",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isModelConfig(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetModelName(t *testing.T) {
	tests := []struct {
		name         string
		modelInfo    *pkg.ModelArtifact
		expectedName string
	}{
		{
			name: "simple name",
			modelInfo: &pkg.ModelArtifact{
				Name: "bert-base-uncased",
			},
			expectedName: "bert-base-uncased",
		},
		{
			name: "path-like name",
			modelInfo: &pkg.ModelArtifact{
				Name: "microsoft/DialoGPT-medium",
			},
			expectedName: "DialoGPT-medium",
		},
		{
			name: "fallback to directory name",
			modelInfo: &pkg.ModelArtifact{
				ConfigPath: "/models/my-model/config.json",
			},
			expectedName: "my-model",
		},
		{
			name:         "fallback to unknown",
			modelInfo:    &pkg.ModelArtifact{},
			expectedName: "unknown-model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getModelName(tt.modelInfo)
			assert.Equal(t, tt.expectedName, result)
		})
	}
}
