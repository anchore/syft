package aiartifact

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestParseGGUFHeader(t *testing.T) {
	tests := []struct {
		name      string
		buildData func() []byte
		wantMeta  *pkg.GGUFFileMetadata
		wantErr   bool
	}{
		{
			name: "standard GGUF with all fields",
			buildData: func() []byte {
				return newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(291).
					withStringKV("general.architecture", "llama").
					withStringKV("general.name", "llama3-8b-instruct").
					withStringKV("general.version", "3.0").
					withStringKV("general.license", "Apache-2.0").
					withStringKV("general.quantization", "Q4_K_M").
					withUint64KV("general.parameter_count", 8030000000).
					build()
			},
			wantMeta: &pkg.GGUFFileMetadata{
				ModelFormat:     "gguf",
				ModelName:       "llama3-8b-instruct",
				ModelVersion:    "3.0",
				License:         "Apache-2.0",
				Architecture:    "llama",
				Quantization:    "Q4_K_M",
				Parameters:      8030000000,
				GGUFVersion:     3,
				TensorCount:     291,
				Header:          map[string]any{},
				TruncatedHeader: false,
			},
		},
		{
			name: "minimal GGUF with only architecture",
			buildData: func() []byte {
				return newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(100).
					withStringKV("general.architecture", "qwen").
					withStringKV("general.name", "qwen2-1.5b").
					build()
			},
			wantMeta: &pkg.GGUFFileMetadata{
				ModelFormat:     "gguf",
				ModelName:       "qwen2-1.5b",
				ModelVersion:    unkownGGUFData,
				Architecture:    "qwen",
				Quantization:    unkownGGUFData,
				GGUFVersion:     3,
				TensorCount:     100,
				Header:          map[string]any{},
				TruncatedHeader: false,
			},
		},
		{
			name: "GGUF v2 (older version)",
			buildData: func() []byte {
				return newTestGGUFBuilder().
					withVersion(2).
					withTensorCount(50).
					withStringKV("general.architecture", "gpt2").
					withStringKV("general.name", "gpt2-small").
					build()
			},
			wantMeta: &pkg.GGUFFileMetadata{
				ModelFormat:     "gguf",
				ModelName:       "gpt2-small",
				ModelVersion:    unkownGGUFData,
				Architecture:    "gpt2",
				Quantization:    unkownGGUFData,
				GGUFVersion:     2,
				TensorCount:     50,
				Header:          map[string]any{},
				TruncatedHeader: false,
			},
		},
		{
			name: "GGUF without general.name falls back to location",
			buildData: func() []byte {
				return newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(150).
					withStringKV("general.architecture", "llama").
					withStringKV("general.license", "MIT").
					build()
			},
			wantMeta: &pkg.GGUFFileMetadata{
				ModelFormat:     "gguf",
				ModelName:       "test-model", // will be extracted from location
				ModelVersion:    unkownGGUFData,
				Architecture:    "llama",
				License:         "MIT",
				Quantization:    unkownGGUFData,
				GGUFVersion:     3,
				TensorCount:     150,
				Header:          map[string]any{},
				TruncatedHeader: false,
			},
		},
		{
			name: "GGUF with extra metadata fields in header",
			buildData: func() []byte {
				return newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(200).
					withStringKV("general.architecture", "mistral").
					withStringKV("general.name", "mistral-7b").
					withStringKV("llama.attention.head_count", "32").
					withStringKV("llama.embedding_length", "4096").
					build()
			},
			wantMeta: &pkg.GGUFFileMetadata{
				ModelFormat:  "gguf",
				ModelName:    "mistral-7b",
				ModelVersion: unkownGGUFData,
				Architecture: "mistral",
				Quantization: unkownGGUFData,
				GGUFVersion:  3,
				TensorCount:  200,
				Header: map[string]any{
					"llama.attention.head_count": "32",
					"llama.embedding_length":     "4096",
				},
				TruncatedHeader: false,
			},
		},
		{
			name: "invalid magic number",
			buildData: func() []byte {
				return newTestGGUFBuilder().buildInvalidMagic()
			},
			wantErr: true,
		},
		{
			name: "truncated file (too small)",
			buildData: func() []byte {
				return []byte{0x47, 0x47}
			},
			wantErr: true,
		},
		{
			name: "empty file",
			buildData: func() []byte {
				return []byte{}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			got, err := parseGGUFHeader(data, "/path/to/test-model.gguf")

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)

			// Don't compare Hash as it's computed
			assert.Equal(t, tt.wantMeta.ModelFormat, got.ModelFormat)
			assert.Equal(t, tt.wantMeta.ModelVersion, got.ModelVersion)
			assert.Equal(t, tt.wantMeta.Architecture, got.Architecture)
			assert.Equal(t, tt.wantMeta.Quantization, got.Quantization)
			assert.Equal(t, tt.wantMeta.GGUFVersion, got.GGUFVersion)
			assert.Equal(t, tt.wantMeta.TensorCount, got.TensorCount)
			assert.Equal(t, tt.wantMeta.Parameters, got.Parameters)
			assert.Equal(t, tt.wantMeta.License, got.License)
			assert.Equal(t, tt.wantMeta.TruncatedHeader, got.TruncatedHeader)

			// For the case without general.name, check that filename was used
			if tt.name == "GGUF without general.name falls back to location" {
				assert.Equal(t, "test-model", got.ModelName)
			} else if tt.wantMeta.ModelName != "" {
				assert.Equal(t, tt.wantMeta.ModelName, got.ModelName)
			}

			// Check Header map
			for k, v := range tt.wantMeta.Header {
				assert.Equal(t, v, got.Header[k], "Header key %s mismatch", k)
			}

			// Hash should be computed
			if !tt.wantErr {
				assert.NotEmpty(t, got.Hash)
			}
		})
	}
}

func TestReadValue(t *testing.T) {
	tests := []struct {
		name      string
		valueType uint32
		buildData func() []byte
		want      interface{}
		wantErr   bool
	}{
		{
			name:      "uint8",
			valueType: ggufTypeUint8,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint8(42))
				return buf.Bytes()
			},
			want: uint8(42),
		},
		{
			name:      "int8",
			valueType: ggufTypeInt8,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, int8(-42))
				return buf.Bytes()
			},
			want: int8(-42),
		},
		{
			name:      "uint32",
			valueType: ggufTypeUint32,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint32(12345))
				return buf.Bytes()
			},
			want: uint32(12345),
		},
		{
			name:      "uint64",
			valueType: ggufTypeUint64,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint64(9876543210))
				return buf.Bytes()
			},
			want: uint64(9876543210),
		},
		{
			name:      "float32",
			valueType: ggufTypeFloat32,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, float32(3.14159))
				return buf.Bytes()
			},
			want: float32(3.14159),
		},
		{
			name:      "bool true",
			valueType: ggufTypeBool,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint8(1))
				return buf.Bytes()
			},
			want: true,
		},
		{
			name:      "bool false",
			valueType: ggufTypeBool,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint8(0))
				return buf.Bytes()
			},
			want: false,
		},
		{
			name:      "string",
			valueType: ggufTypeString,
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				s := "hello world"
				binary.Write(buf, binary.LittleEndian, uint64(len(s)))
				buf.WriteString(s)
				return buf.Bytes()
			},
			want: "hello world",
		},
		{
			name:      "unknown type",
			valueType: 99,
			buildData: func() []byte {
				return []byte{}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			reader := bytes.NewReader(data)

			got, err := readValue(reader, tt.valueType)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadString(t *testing.T) {
	tests := []struct {
		name      string
		buildData func() []byte
		want      string
		wantErr   bool
	}{
		{
			name: "normal string",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				s := "test string"
				binary.Write(buf, binary.LittleEndian, uint64(len(s)))
				buf.WriteString(s)
				return buf.Bytes()
			},
			want: "test string",
		},
		{
			name: "empty string",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint64(0))
				return buf.Bytes()
			},
			want: "",
		},
		{
			name: "string exceeds max length",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint64(maxKeyLen+1))
				return buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "truncated string data",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint64(100))
				buf.WriteString("short")
				return buf.Bytes()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			reader := bytes.NewReader(data)

			got, err := readString(reader)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadArray(t *testing.T) {
	tests := []struct {
		name      string
		buildData func() []byte
		want      interface{}
		wantErr   bool
	}{
		{
			name: "array of uint32",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint32(ggufTypeUint32)) // element type
				binary.Write(buf, binary.LittleEndian, uint64(3))              // array length
				binary.Write(buf, binary.LittleEndian, uint32(1))
				binary.Write(buf, binary.LittleEndian, uint32(2))
				binary.Write(buf, binary.LittleEndian, uint32(3))
				return buf.Bytes()
			},
			want: []interface{}{uint32(1), uint32(2), uint32(3)},
		},
		{
			name: "empty array",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint32(ggufTypeUint32))
				binary.Write(buf, binary.LittleEndian, uint64(0))
				return buf.Bytes()
			},
			want: ([]interface{})(nil), // Empty array returns nil slice
		},
		{
			name: "array too large",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint32(ggufTypeUint32))
				binary.Write(buf, binary.LittleEndian, uint64(10000))
				return buf.Bytes()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			reader := bytes.NewReader(data)

			got, err := readArray(reader)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadKVPair(t *testing.T) {
	tests := []struct {
		name      string
		buildData func() []byte
		wantKey   string
		wantValue interface{}
		wantErr   bool
	}{
		{
			name: "string key-value pair",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				// Write key
				key := "general.name"
				binary.Write(buf, binary.LittleEndian, uint64(len(key)))
				buf.WriteString(key)
				// Write value type
				binary.Write(buf, binary.LittleEndian, uint32(ggufTypeString))
				// Write value
				value := "test-model"
				binary.Write(buf, binary.LittleEndian, uint64(len(value)))
				buf.WriteString(value)
				return buf.Bytes()
			},
			wantKey:   "general.name",
			wantValue: "test-model",
		},
		{
			name: "uint64 key-value pair",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				// Write key
				key := "general.parameter_count"
				binary.Write(buf, binary.LittleEndian, uint64(len(key)))
				buf.WriteString(key)
				// Write value type
				binary.Write(buf, binary.LittleEndian, uint32(ggufTypeUint64))
				// Write value
				binary.Write(buf, binary.LittleEndian, uint64(7000000000))
				return buf.Bytes()
			},
			wantKey:   "general.parameter_count",
			wantValue: uint64(7000000000),
		},
		{
			name: "key too long",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint64(maxKeyLen+1))
				return buf.Bytes()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			reader := bytes.NewReader(data)

			gotKey, gotValue, err := readKVPair(reader)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantKey, gotKey)
			assert.Equal(t, tt.wantValue, gotValue)
		})
	}
}

func TestInferQuantizationFromFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{
			name:     "Q4_K_M quantization",
			filename: "/path/to/model-Q4_K_M.gguf",
			want:     "Q4_K_M",
		},
		{
			name:     "IQ4_NL quantization",
			filename: "/path/to/model-IQ4_NL.gguf",
			want:     "Q4_NL", // The regex [IQ]\d+_[A-Z_]+ matches Q4_NL from IQ4_NL
		},
		{
			name:     "Q5_K_S quantization",
			filename: "mistral-7b-Q5_K_S.gguf",
			want:     "Q5_K_S",
		},
		{
			name:     "no quantization in filename",
			filename: "/path/to/model.gguf",
			want:     unkownGGUFData,
		},
		{
			name:     "partial match should not match",
			filename: "/path/to/Q4-model.gguf",
			want:     unkownGGUFData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferQuantizationFromFilename(tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestComputeMetadataHash(t *testing.T) {
	tests := []struct {
		name     string
		metadata *pkg.GGUFFileMetadata
		wantLen  int
	}{
		{
			name: "hash should be consistent",
			metadata: &pkg.GGUFFileMetadata{
				ModelFormat:  "gguf",
				ModelName:    "test-model",
				ModelVersion: "1.0",
				Architecture: "llama",
				GGUFVersion:  3,
				TensorCount:  100,
			},
			wantLen: 16, // 8 bytes = 16 hex chars
		},
		{
			name: "different metadata produces different hash",
			metadata: &pkg.GGUFFileMetadata{
				ModelFormat:  "gguf",
				ModelName:    "different-model",
				ModelVersion: "2.0",
				Architecture: "gpt2",
				GGUFVersion:  2,
				TensorCount:  200,
			},
			wantLen: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := computeMetadataHash(tt.metadata)
			assert.Len(t, hash, tt.wantLen)
			assert.NotEmpty(t, hash)
		})
	}

	// Test that same metadata produces same hash
	meta1 := &pkg.GGUFFileMetadata{
		ModelFormat:  "gguf",
		ModelName:    "test",
		ModelVersion: "1.0",
		Architecture: "llama",
		GGUFVersion:  3,
		TensorCount:  100,
	}
	meta2 := &pkg.GGUFFileMetadata{
		ModelFormat:  "gguf",
		ModelName:    "test",
		ModelVersion: "1.0",
		Architecture: "llama",
		GGUFVersion:  3,
		TensorCount:  100,
	}
	hash1 := computeMetadataHash(meta1)
	hash2 := computeMetadataHash(meta2)
	assert.Equal(t, hash1, hash2, "identical metadata should produce identical hash")

	// Test that different metadata produces different hash
	meta3 := &pkg.GGUFFileMetadata{
		ModelFormat:  "gguf",
		ModelName:    "different",
		ModelVersion: "1.0",
		Architecture: "llama",
		GGUFVersion:  3,
		TensorCount:  100,
	}
	hash3 := computeMetadataHash(meta3)
	assert.NotEqual(t, hash1, hash3, "different metadata should produce different hash")
}

func TestParseGGUFHeader_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		buildData func() []byte
		location  string
		wantErr   bool
		checkFunc func(t *testing.T, meta *pkg.GGUFFileMetadata)
	}{
		{
			name: "excessive KV pairs should error",
			buildData: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint32(ggufMagic))
				binary.Write(buf, binary.LittleEndian, uint32(3))
				binary.Write(buf, binary.LittleEndian, uint64(100))
				binary.Write(buf, binary.LittleEndian, uint64(maxKVPairs+1)) // Too many
				return buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "tensor count at maximum should succeed",
			buildData: func() []byte {
				return newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(maxTensors).
					withStringKV("general.architecture", "llama").
					withStringKV("general.name", "large-model").
					build()
			},
			wantErr: false,
			checkFunc: func(t *testing.T, meta *pkg.GGUFFileMetadata) {
				assert.Equal(t, uint64(maxTensors), meta.TensorCount)
			},
		},
		{
			name: "tensor count exceeds maximum should be capped",
			buildData: func() []byte {
				return newTestGGUFBuilder().
					withVersion(3).
					withTensorCount(maxTensors+1000).
					withStringKV("general.architecture", "llama").
					withStringKV("general.name", "huge-model").
					build()
			},
			wantErr: false,
			checkFunc: func(t *testing.T, meta *pkg.GGUFFileMetadata) {
				assert.Equal(t, uint64(maxTensors), meta.TensorCount)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			location := tt.location
			if location == "" {
				location = "/test/path.gguf"
			}

			got, err := parseGGUFHeader(data, location)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.checkFunc != nil {
				tt.checkFunc(t, got)
			}
		})
	}
}

func TestReadValue_EOF(t *testing.T) {
	// Test that reading beyond available data returns appropriate errors
	tests := []struct {
		name      string
		valueType uint32
		data      []byte
	}{
		{
			name:      "EOF reading uint32",
			valueType: ggufTypeUint32,
			data:      []byte{0x01}, // Only 1 byte, need 4
		},
		{
			name:      "EOF reading string length",
			valueType: ggufTypeString,
			data:      []byte{0x01}, // Incomplete length
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			_, err := readValue(reader, tt.valueType)
			assert.Error(t, err)
			assert.True(t, err == io.EOF || err == io.ErrUnexpectedEOF || bytes.Contains([]byte(err.Error()), []byte("EOF")))
		})
	}
}

// ============================================================================
// Integration Tests for parseGGUFModel
// ============================================================================

func TestParseGGUFModel(t *testing.T) {
	tests := []struct {
		name                  string
		fixture               func(t *testing.T) string // returns path to temp fixture
		expectedPackages      []pkg.Package
		expectedRelationships []artifact.Relationship
		wantErr               bool
	}{
		{
			name: "valid GGUF with complete metadata",
			fixture: func(t *testing.T) string {
				return createTempGGUFFile(t, "llama3-8b-q4.gguf",
					newTestGGUFBuilder().
						withVersion(3).
						withTensorCount(291).
						withStringKV("general.architecture", "llama").
						withStringKV("general.name", "llama3-8b-instruct").
						withStringKV("general.version", "3.0").
						withStringKV("general.license", "Apache-2.0").
						withStringKV("general.quantization", "Q4_K_M").
						withUint64KV("general.parameter_count", 8030000000).
						build(),
				)
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "llama3-8b-instruct",
					Version: "3.0",
					Type:    pkg.ModelPkg,
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "llama3-8b-instruct",
						ModelVersion:    "3.0",
						License:         "Apache-2.0",
						Architecture:    "llama",
						Quantization:    "Q4_K_M",
						Parameters:      8030000000,
						GGUFVersion:     3,
						TensorCount:     291,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
					},
				},
			},
		},
		{
			name: "minimal GGUF file",
			fixture: func(t *testing.T) string {
				return createTempGGUFFile(t, "minimal.gguf",
					newTestGGUFBuilder().
						withVersion(3).
						withTensorCount(100).
						withStringKV("general.architecture", "qwen").
						withStringKV("general.name", "qwen2-1.5b").
						build(),
				)
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "qwen2-1.5b",
					Version: unkownGGUFData,
					Type:    pkg.ModelPkg,
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "qwen2-1.5b",
						ModelVersion:    unkownGGUFData,
						Architecture:    "qwen",
						Quantization:    unkownGGUFData,
						GGUFVersion:     3,
						TensorCount:     100,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
					},
				},
			},
		},
		{
			name: "GGUF without general.name uses filename",
			fixture: func(t *testing.T) string {
				return createTempGGUFFile(t, "inferred-name-model.gguf",
					newTestGGUFBuilder().
						withVersion(3).
						withTensorCount(150).
						withStringKV("general.architecture", "llama").
						withStringKV("general.license", "MIT").
						build(),
				)
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "inferred-name-model",
					Version: unkownGGUFData,
					Type:    pkg.ModelPkg,
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "inferred-name-model",
						ModelVersion:    unkownGGUFData,
						License:         "MIT",
						Architecture:    "llama",
						Quantization:    unkownGGUFData,
						GGUFVersion:     3,
						TensorCount:     150,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
					},
				},
			},
		},
		{
			name: "GGUF with quantization inferred from filename",
			fixture: func(t *testing.T) string {
				return createTempGGUFFile(t, "mistral-7b-Q4_K_M.gguf",
					newTestGGUFBuilder().
						withVersion(3).
						withTensorCount(219).
						withStringKV("general.architecture", "mistral").
						withStringKV("general.name", "mistral-7b-instruct").
						withStringKV("general.version", "0.2").
						withUint64KV("general.parameter_count", 7240000000).
						withStringKV("general.quantized_by", "llama.cpp"). // Triggers filename inference
						build(),
				)
			},
			expectedPackages: []pkg.Package{
				{
					Name:    "mistral-7b-instruct",
					Version: "0.2",
					Type:    pkg.ModelPkg,
					Metadata: pkg.GGUFFileMetadata{
						ModelFormat:     "gguf",
						ModelName:       "mistral-7b-instruct",
						ModelVersion:    "0.2",
						Architecture:    "mistral",
						Quantization:    "Q4_K_M",
						Parameters:      7240000000,
						GGUFVersion:     3,
						TensorCount:     219,
						Header:          map[string]interface{}{},
						TruncatedHeader: false,
					},
				},
			},
		},
		{
			name: "invalid GGUF magic number",
			fixture: func(t *testing.T) string {
				return createTempGGUFFile(t, "invalid-magic.gguf",
					newTestGGUFBuilder().buildInvalidMagic(),
				)
			},
			wantErr: true,
		},
		{
			name: "truncated GGUF file",
			fixture: func(t *testing.T) string {
				return createTempGGUFFile(t, "truncated.gguf", []byte{0x47, 0x47})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixturePath := tt.fixture(t)
			defer os.Remove(fixturePath)

			f, err := os.Open(fixturePath)
			require.NoError(t, err)
			defer f.Close()

			location := file.NewLocation(fixturePath)
			reader := file.LocationReadCloser{
				Location:   location,
				ReadCloser: f,
			}

			ctx := context.Background()
			pkgs, relationships, err := parseGGUFModel(ctx, nil, nil, reader)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, pkgs, len(tt.expectedPackages))

			// Compare packages (ignoring Hash which is computed)
			for i, expectedPkg := range tt.expectedPackages {
				actualPkg := pkgs[i]

				assert.Equal(t, expectedPkg.Name, actualPkg.Name)
				assert.Equal(t, expectedPkg.Version, actualPkg.Version)
				assert.Equal(t, expectedPkg.Type, actualPkg.Type)
				assert.Empty(t, actualPkg.PURL, "PURL should not be set for model packages")

				// Check metadata
				actualMeta, ok := actualPkg.Metadata.(pkg.GGUFFileMetadata)
				require.True(t, ok)
				expectedMeta := expectedPkg.Metadata.(pkg.GGUFFileMetadata)

				assert.Equal(t, expectedMeta.ModelFormat, actualMeta.ModelFormat)
				assert.Equal(t, expectedMeta.ModelName, actualMeta.ModelName)
				assert.Equal(t, expectedMeta.ModelVersion, actualMeta.ModelVersion)
				assert.Equal(t, expectedMeta.License, actualMeta.License)
				assert.Equal(t, expectedMeta.Architecture, actualMeta.Architecture)
				assert.Equal(t, expectedMeta.Quantization, actualMeta.Quantization)
				assert.Equal(t, expectedMeta.Parameters, actualMeta.Parameters)
				assert.Equal(t, expectedMeta.GGUFVersion, actualMeta.GGUFVersion)
				assert.Equal(t, expectedMeta.TensorCount, actualMeta.TensorCount)
				assert.Equal(t, expectedMeta.TruncatedHeader, actualMeta.TruncatedHeader)

				// Hash should be computed
				assert.NotEmpty(t, actualMeta.Hash)
			}

			assert.Equal(t, tt.expectedRelationships, relationships)
		})
	}
}

func TestParseGGUFModel_HeaderReadLimit(t *testing.T) {
	builder := newTestGGUFBuilder().
		withVersion(3).
		withTensorCount(100).
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "large-header-model")

	// Add many additional fields
	for i := 0; i < 50; i++ {
		builder.withStringKV("custom.field"+string(rune(i)), "value")
	}

	fixturePath := createTempGGUFFile(t, "large-header.gguf", builder.build())
	defer os.Remove(fixturePath)

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer f.Close()

	reader := file.LocationReadCloser{
		Location:   file.NewLocation(fixturePath),
		ReadCloser: f,
	}

	ctx := context.Background()
	pkgs, _, err := parseGGUFModel(ctx, nil, nil, reader)

	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "large-header-model", pkgs[0].Name)
}

func TestParseGGUFModel_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	fixturePath := filepath.Join(tmpDir, "empty.gguf")
	err := os.WriteFile(fixturePath, []byte{}, 0644)
	require.NoError(t, err)

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer f.Close()

	reader := file.LocationReadCloser{
		Location:   file.NewLocation(fixturePath),
		ReadCloser: f,
	}

	ctx := context.Background()
	_, _, err = parseGGUFModel(ctx, nil, nil, reader)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

func TestParseGGUFModel_LargeFile(t *testing.T) {
	// Test that we only read the header, not the entire file
	builder := newTestGGUFBuilder().
		withVersion(3).
		withTensorCount(100).
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "test-model")

	headerData := builder.build()

	// Create a file with header + large padding
	tmpDir := t.TempDir()
	fixturePath := filepath.Join(tmpDir, "large.gguf")
	f, err := os.Create(fixturePath)
	require.NoError(t, err)

	_, err = f.Write(headerData)
	require.NoError(t, err)

	// Write 20MB of padding (simulating tensor data)
	padding := make([]byte, 20*1024*1024)
	_, err = f.Write(padding)
	require.NoError(t, err)
	f.Close()

	// Parse the file
	f, err = os.Open(fixturePath)
	require.NoError(t, err)
	defer f.Close()

	reader := file.LocationReadCloser{
		Location:   file.NewLocation(fixturePath),
		ReadCloser: f,
	}

	ctx := context.Background()
	pkgs, _, err := parseGGUFModel(ctx, nil, nil, reader)

	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "test-model", pkgs[0].Name)
}

func Test_parseGGUFModel_interface(t *testing.T) {
	// This test ensures parseGGUFModel matches the generic.Parser signature
	fixture := createTempGGUFFile(t, "interface-test.gguf",
		newTestGGUFBuilder().
			withVersion(3).
			withTensorCount(100).
			withStringKV("general.architecture", "llama").
			withStringKV("general.name", "test").
			build(),
	)
	defer os.Remove(fixture)

	f, err := os.Open(fixture)
	require.NoError(t, err)
	defer f.Close()

	reader := file.LocationReadCloser{
		Location:   file.NewLocation(fixture),
		ReadCloser: f,
	}

	ctx := context.Background()
	pkgs, rels, err := parseGGUFModel(ctx, nil, nil, reader)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Empty(t, rels)

	// Verify basic package structure
	assert.Equal(t, "test", pkgs[0].Name)
	assert.Equal(t, unkownGGUFData, pkgs[0].Version)
	assert.Equal(t, pkg.ModelPkg, pkgs[0].Type)
}

func TestParseGGUFModel_ReaderClosed(t *testing.T) {
	// Ensure the reader is properly closed after parsing
	fixture := createTempGGUFFile(t, "close-test.gguf",
		newTestGGUFBuilder().
			withVersion(3).
			withTensorCount(100).
			withStringKV("general.architecture", "llama").
			withStringKV("general.name", "test").
			build(),
	)
	defer os.Remove(fixture)

	f, err := os.Open(fixture)
	require.NoError(t, err)

	// Wrap in a custom closer to track if Close was called
	closeCalled := false
	reader := file.LocationReadCloser{
		Location: file.NewLocation(fixture),
		ReadCloser: &testReadCloser{
			Reader: f,
			onClose: func() error {
				closeCalled = true
				return f.Close()
			},
		},
	}

	ctx := context.Background()
	_, _, err = parseGGUFModel(ctx, nil, nil, reader)
	require.NoError(t, err)

	assert.True(t, closeCalled, "reader should be closed after parsing")
}

// createTempGGUFFile creates a temporary GGUF file for testing
func createTempGGUFFile(t *testing.T, filename string, data []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, filename)
	err := os.WriteFile(path, data, 0644)
	require.NoError(t, err)
	return path
}

// testReadCloser wraps an io.Reader and tracks Close calls
type testReadCloser struct {
	io.Reader
	onClose func() error
}

func (r *testReadCloser) Close() error {
	if r.onClose != nil {
		return r.onClose()
	}
	return nil
}
