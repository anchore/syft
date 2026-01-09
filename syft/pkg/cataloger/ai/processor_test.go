package ai

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func TestGgufMergeProcessor(t *testing.T) {
	tests := []struct {
		name         string
		inputPkgs    []pkg.Package
		inputRels    []artifact.Relationship
		inputErr     error
		expectedPkgs []pkg.Package
		expectedRels []artifact.Relationship
		expectedErr  error
	}{
		{
			name:         "returns early when error is passed",
			inputPkgs:    []pkg.Package{{Name: "test"}},
			inputRels:    []artifact.Relationship{},
			inputErr:     errors.New("some error"),
			expectedPkgs: []pkg.Package{{Name: "test"}},
			expectedRels: []artifact.Relationship{},
			expectedErr:  errors.New("some error"),
		},
		{
			name:         "returns early when no packages",
			inputPkgs:    []pkg.Package{},
			inputRels:    []artifact.Relationship{},
			inputErr:     nil,
			expectedPkgs: []pkg.Package{},
			expectedRels: []artifact.Relationship{},
			expectedErr:  nil,
		},
		{
			name: "returns nil when no named packages",
			inputPkgs: []pkg.Package{
				{
					Name:     "",
					Metadata: pkg.GGUFFileHeader{Architecture: "llama"},
				},
				{
					Name:     "",
					Metadata: pkg.GGUFFileHeader{Architecture: "gpt2"},
				},
			},
			inputRels:    []artifact.Relationship{},
			inputErr:     nil,
			expectedPkgs: nil,
			expectedRels: []artifact.Relationship{},
			expectedErr:  nil,
		},
		{
			name: "merges nameless headers into single named package",
			inputPkgs: []pkg.Package{
				{
					Name: "llama-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "llama",
						MetadataKeyValuesHash: "abc123",
					},
				},
				{
					Name: "",
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "llama",
						Quantization:          "Q4_K_M",
						MetadataKeyValuesHash: "def456",
					},
				},
				{
					Name: "",
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "llama",
						Quantization:          "Q8_0",
						MetadataKeyValuesHash: "ghi789",
					},
				},
			},
			inputRels: []artifact.Relationship{},
			inputErr:  nil,
			expectedPkgs: []pkg.Package{
				{
					Name: "llama-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture:          "llama",
						MetadataKeyValuesHash: "abc123",
						GGUFFileHeaders: []pkg.GGUFFileHeader{
							{
								Architecture:          "llama",
								Quantization:          "Q4_K_M",
								MetadataKeyValuesHash: "",
							},
							{
								Architecture:          "llama",
								Quantization:          "Q8_0",
								MetadataKeyValuesHash: "",
							},
						},
					},
				},
			},
			expectedRels: []artifact.Relationship{},
			expectedErr:  nil,
		},
		{
			name: "returns multiple named packages without merging",
			inputPkgs: []pkg.Package{
				{
					Name: "llama-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "llama",
					},
				},
				{
					Name: "gpt2-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "gpt2",
					},
				},
				{
					Name: "",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "unknown",
					},
				},
			},
			inputRels: []artifact.Relationship{},
			inputErr:  nil,
			expectedPkgs: []pkg.Package{
				{
					Name: "llama-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "llama",
					},
				},
				{
					Name: "gpt2-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "gpt2",
					},
				},
			},
			expectedRels: []artifact.Relationship{},
			expectedErr:  nil,
		},
		{
			name: "preserves relationships",
			inputPkgs: []pkg.Package{
				{
					Name: "test-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "test",
					},
				},
			},
			inputRels: []artifact.Relationship{
				{Type: artifact.ContainsRelationship},
			},
			inputErr: nil,
			expectedPkgs: []pkg.Package{
				{
					Name: "test-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "test",
					},
				},
			},
			expectedRels: []artifact.Relationship{
				{Type: artifact.ContainsRelationship},
			},
			expectedErr: nil,
		},
		{
			name: "handles non-GGUF metadata in nameless packages",
			inputPkgs: []pkg.Package{
				{
					Name: "named-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "llama",
					},
				},
				{
					Name:     "",
					Metadata: "not a GGUFFileHeader",
				},
			},
			inputRels: []artifact.Relationship{},
			inputErr:  nil,
			expectedPkgs: []pkg.Package{
				{
					Name: "named-model",
					Metadata: pkg.GGUFFileHeader{
						Architecture: "llama",
					},
				},
			},
			expectedRels: []artifact.Relationship{},
			expectedErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultPkgs, resultRels, resultErr := ggufMergeProcessor(tt.inputPkgs, tt.inputRels, tt.inputErr)

			if tt.expectedErr != nil {
				require.Error(t, resultErr)
				assert.Equal(t, tt.expectedErr.Error(), resultErr.Error())
			} else {
				require.NoError(t, resultErr)
			}

			assert.Equal(t, tt.expectedRels, resultRels)

			require.Len(t, resultPkgs, len(tt.expectedPkgs))
			for i, expectedPkg := range tt.expectedPkgs {
				assert.Equal(t, expectedPkg.Name, resultPkgs[i].Name)

				expectedMeta, ok := expectedPkg.Metadata.(pkg.GGUFFileHeader)
				if ok {
					actualMeta, ok := resultPkgs[i].Metadata.(pkg.GGUFFileHeader)
					require.True(t, ok, "expected GGUFFileHeader metadata")
					assert.Equal(t, expectedMeta.Architecture, actualMeta.Architecture)
					assert.Equal(t, expectedMeta.MetadataKeyValuesHash, actualMeta.MetadataKeyValuesHash)
					assert.Equal(t, len(expectedMeta.GGUFFileHeaders), len(actualMeta.GGUFFileHeaders))

					for j, expectedHeader := range expectedMeta.GGUFFileHeaders {
						assert.Equal(t, expectedHeader.Architecture, actualMeta.GGUFFileHeaders[j].Architecture)
						assert.Equal(t, expectedHeader.Quantization, actualMeta.GGUFFileHeaders[j].Quantization)
						assert.Empty(t, actualMeta.GGUFFileHeaders[j].MetadataKeyValuesHash, "nameless header hash should be cleared")
					}
				}
			}
		})
	}
}
