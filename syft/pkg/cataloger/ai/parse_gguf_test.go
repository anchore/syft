package ai

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"strings"
	"testing"

	gguf_parser "github.com/gpustack/gguf-parser-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func le(v any) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, v)
	return buf.Bytes()
}

func ggufString(s string) []byte {
	return append(le(uint64(len(s))), s...)
}

func parseGGUFBytes(t *testing.T, data []byte) ([]pkg.Package, error) {
	t.Helper()
	ctx, td := tmpdir.Root(context.Background(), "gguf-test")
	t.Cleanup(func() { _ = td.Cleanup() })
	reader := file.NewLocationReadCloser(file.NewLocation("/model.gguf"), io.NopCloser(bytes.NewReader(data)))
	var pkgs []pkg.Package
	var err error
	require.NotPanics(t, func() {
		pkgs, _, err = parseGGUFModel(ctx, nil, nil, reader)
	})
	return pkgs, err
}

func TestParseGGUFModel_malformedHeader(t *testing.T) {
	// nested arrays of arrays, each one level deeper, ending in an empty uint8 array
	nested := func(depth int) []byte {
		v := ggufArray(ggufTypeUint8, 0, nil)
		for i := 1; i < depth; i++ {
			v = ggufArray(ggufTypeArray, 1, v)
		}
		return v
	}

	// a header that declares more KVs than the cap, with none following
	tooManyKVs := append(append([]byte("GGUF"), le(uint32(3))...), le([]uint64{0, maxGGUFKVCount + 1})...)

	tests := []struct {
		name    string
		builder *testGGUFBuilder
		data    []byte // used instead of builder when set
		wantErr bool
	}{
		{name: "too many KVs", data: tooManyKVs, wantErr: true},
		{name: "split tensor count is a string", builder: newTestGGUFBuilder().withStringKV("split.tensors.count", "1"), wantErr: true},
		{name: "split tensor count over the cap", builder: newTestGGUFBuilder().withUint32KV("split.tensors.count", maxGGUFSplitTensors+1), wantErr: true},
		{name: "read strings too long in total", builder: newTestGGUFBuilder().withStringKV("x", strings.Repeat("a", maxGGUFReadStringBytes)), wantErr: true},
		{
			name:    "skipped strings too many in total",
			builder: newTestGGUFBuilder().withRawKV("tokenizer.ggml.tokens", ggufTypeArray, ggufArray(ggufTypeString, maxGGUFSkippedStrings+1, make([]byte, 8*(maxGGUFSkippedStrings+1)))),
			wantErr: true,
		},
		{name: "v1 header", builder: newTestGGUFBuilder().withVersion(1).withStringKV("general.name", "m").withUint32KV("llama.context_length", 8)},
		{name: "architecture not a string", builder: newTestGGUFBuilder().withUint32KV("general.architecture", 1), wantErr: true},
		{name: "name not a string", builder: newTestGGUFBuilder().withUint32KV("general.name", 1), wantErr: true},
		{name: "license not a string", builder: newTestGGUFBuilder().withUint32KV("general.license", 1), wantErr: true},
		{name: "type not a string", builder: newTestGGUFBuilder().withUint32KV("general.type", 1), wantErr: true},
		{name: "author not a string", builder: newTestGGUFBuilder().withUint32KV("general.author", 1), wantErr: true},
		{name: "url not a string", builder: newTestGGUFBuilder().withUint32KV("general.url", 1), wantErr: true},
		{name: "description not a string", builder: newTestGGUFBuilder().withUint32KV("general.description", 1), wantErr: true},
		{name: "model hint not a string", builder: newTestGGUFBuilder().withUint32KV("controlvector.model_hint", 1), wantErr: true},
		{name: "quantization version is a string", builder: newTestGGUFBuilder().withStringKV("general.quantization_version", "2"), wantErr: true},
		{name: "alignment is a string", builder: newTestGGUFBuilder().withStringKV("general.alignment", "32"), wantErr: true},
		{name: "alignment is uint64", builder: newTestGGUFBuilder().withUint64KV("general.alignment", 32), wantErr: true},
		{name: "alignment is zero", builder: newTestGGUFBuilder().withUint32KV("general.alignment", 0), wantErr: true},
		{
			name:    "array of arrays on a skipped key",
			builder: newTestGGUFBuilder().withRawKV("tokenizer.ggml.merges", ggufTypeArray, ggufArray(ggufTypeArray, 1, ggufArray(ggufTypeUint8, 0, nil))),
			wantErr: true,
		},
		{
			name:    "invalid array item type",
			builder: newTestGGUFBuilder().withRawKV("tokenizer.ggml.scores", ggufTypeArray, ggufArray(99, 0, nil)),
			wantErr: true,
		},
		{name: "split tensor count out of range", builder: newTestGGUFBuilder().withUint64KV("split.tensors.count", 1<<62), wantErr: true},
		{name: "split tensor count huge", builder: newTestGGUFBuilder().withUint64KV("split.tensors.count", 1<<40), wantErr: true},
		{name: "split tensor count negative", builder: newTestGGUFBuilder().withRawKV("split.tensors.count", ggufTypeInt64, le(int64(-1))), wantErr: true},
		{
			name:    "nesting too deep on a decoded key",
			builder: newTestGGUFBuilder().withRawKV("llama.attention.head_count", ggufTypeArray, nested(3)),
			wantErr: true,
		},
		{
			name:    "decoded array too long",
			builder: newTestGGUFBuilder().withRawKV("llama.feed_forward_length", ggufTypeArray, ggufArray(ggufTypeUint8, maxGGUFDecodedItems+1, make([]byte, maxGGUFDecodedItems+1))),
			wantErr: true,
		},
		{name: "empty string value", builder: newTestGGUFBuilder().withStringKV("general.author", ""), wantErr: true},
		{name: "padded key", builder: newTestGGUFBuilder().withUint32KV(" general.alignment\t", 0), wantErr: true},
		{name: "long padded key", builder: newTestGGUFBuilder().withUint32KV(strings.Repeat(" ", 300)+"general.alignment", 0), wantErr: true},
		{name: "file type is a string", builder: newTestGGUFBuilder().withUint32KV("general.file_type", 1).withStringKV("general.file_type", "x"), wantErr: true},
		{
			name: "decoded arrays too long in total",
			builder: newTestGGUFBuilder().
				withRawKV("a.feed_forward_length", ggufTypeArray, ggufArray(ggufTypeUint8, maxGGUFDecodedItems, make([]byte, maxGGUFDecodedItems))).
				withRawKV("b.feed_forward_length", ggufTypeArray, ggufArray(ggufTypeUint8, 1, make([]byte, 1))),
			wantErr: true,
		},
		{name: "invalid value type", builder: newTestGGUFBuilder().withRawKV("x", 0xFFFFFFFF, nil), wantErr: true},
		{name: "empty key", builder: newTestGGUFBuilder().withUint32KV("", 1), wantErr: true},
		{
			name:    "empty string in a decoded array",
			builder: newTestGGUFBuilder().withRawKV("llama.attention.head_count", ggufTypeArray, ggufArray(ggufTypeString, 1, le(uint64(0)))),
			wantErr: true,
		},
		{
			name:    "empty string in a skipped array",
			builder: newTestGGUFBuilder().withRawKV("tokenizer.ggml.tokens", ggufTypeArray, ggufArray(ggufTypeString, 1, le(uint64(0)))),
		},
		{
			name:    "array of arrays on a decoded key",
			builder: newTestGGUFBuilder().withRawKV("llama.attention.head_count", ggufTypeArray, nested(2)),
		},
		{name: "alignment is a uint32", builder: newTestGGUFBuilder().withUint32KV("general.alignment", 32)},
		{
			name: "split keys as written by llama.cpp",
			builder: newTestGGUFBuilder().
				withRawKV("split.no", ggufTypeUint16, le(uint16(0))).
				withRawKV("split.count", ggufTypeUint16, le(uint16(3))).
				withRawKV("split.tensors.count", ggufTypeInt32, le(int32(3000))),
		},
		{
			name:    "split shard declares the total tensor count",
			builder: newTestGGUFBuilder().withRawKV("split.tensors.count", ggufTypeInt32, le(int32(3000))),
		},
		{
			name:    "skipped scalar array",
			builder: newTestGGUFBuilder().withRawKV("tokenizer.ggml.scores", ggufTypeArray, ggufArray(ggufTypeFloat32, 3, make([]byte, 12))),
		},
		// ponytail: zero block size tensor types and dimension overflow panic inside tensor info parsing;
		// those are left to the generic cataloger's panic handling rather than checked here.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.data
			if data == nil {
				data = tt.builder.withStringKV("general.architecture", "llama").build()
			}
			pkgs, err := parseGGUFBytes(t, data)
			if tt.wantErr {
				// the pre-scan has to be what rejects these, before the library sees them
				require.ErrorContains(t, err, "invalid GGUF header")
				assert.Empty(t, pkgs)
				return
			}
			require.NoError(t, err)
			require.Len(t, pkgs, 1)
		})
	}
}

func TestParseGGUFModel_nonFiniteFloat(t *testing.T) {
	data := newTestGGUFBuilder().
		withStringKV("general.architecture", "llama").
		withRawKV("llama.rope.freq_base", ggufTypeFloat32, le(float32(math.Inf(1)))).
		withRawKV("llama.rope.scale", ggufTypeFloat64, le(math.Inf(-1))).
		withRawKV("llama.attention.head_count", ggufTypeArray, ggufArray(ggufTypeFloat32, 2, le([]float32{8, float32(math.NaN())}))).
		withRawKV("tokenizer.ggml.scores", ggufTypeArray, ggufArray(ggufTypeFloat32, 1, le(float32(0)))).
		build()

	pkgs, err := parseGGUFBytes(t, data)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)

	meta := pkgs[0].Metadata.(pkg.GGUFFileHeader)
	assert.NotEmpty(t, meta.MetadataKeyValuesHash)
	assert.Equal(t, "+Inf", meta.RemainingKeyValues["llama.rope.freq_base"])
	assert.Equal(t, "-Inf", meta.RemainingKeyValues["llama.rope.scale"])
	headCount := meta.RemainingKeyValues["llama.attention.head_count"].(gguf_parser.GGUFMetadataKVArrayValue)
	assert.Equal(t, []any{float32(8), "NaN"}, headCount.Array)

	var buf bytes.Buffer
	s := sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(pkgs...)}}
	require.NoError(t, syftjson.NewFormatEncoder().Encode(&buf, s))
	assert.NotEmpty(t, buf.Bytes())
}

// TestParseGGUFModel_outputUnchanged pins the header output and hash for ordinary values to what syft
// produced as of f7f3c6efc, before malformed header handling. The expected values were captured by
// running this same fixture on that commit. float32 0.1 catches any widening to float64.
func TestParseGGUFModel_outputUnchanged(t *testing.T) {
	data := newTestGGUFBuilder().
		withStringKV("general.architecture", "llama").
		withRawKV("tokenizer.ggml.tokens", ggufTypeArray, ggufArray(ggufTypeString, 2, append(ggufString("a"), ggufString("b")...))).
		withRawKV("llama.attention.head_count", ggufTypeArray, ggufArray(ggufTypeFloat32, 2, le([]float32{0.1, 0.2}))).
		withRawKV("llama.feed_forward_length", ggufTypeArray, ggufArray(ggufTypeArray, 2, append(
			ggufArray(ggufTypeUint32, 2, le([]uint32{1, 2})),
			ggufArray(ggufTypeUint32, 1, le([]uint32{3}))...))).
		withRawKV("llama.rope.freq_base", ggufTypeFloat32, le(float32(0.1))).
		build()

	pkgs, err := parseGGUFBytes(t, data)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)

	meta := pkgs[0].Metadata.(pkg.GGUFFileHeader)
	assert.Equal(t, "4f28d55f0985a985", meta.MetadataKeyValuesHash)
	header, err := json.Marshal(meta.RemainingKeyValues)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"llama.attention.head_count": {"type": 6, "len": 2, "array": [0.1, 0.2], "startOffset": 170, "size": 8},
		"llama.feed_forward_length": {"type": 9, "len": 2, "array": [
			{"type": 4, "len": 2, "array": [1, 2], "startOffset": 239, "size": 8},
			{"type": 4, "len": 1, "array": [3], "startOffset": 259, "size": 4}
		], "startOffset": 227, "size": 36},
		"llama.rope.freq_base": 0.1,
		"tokenizer.ggml.tokens": {"type": 8, "len": 2, "startOffset": 102, "size": 18}
	}`, string(header))
}

// TestCopyHeader_appliesItsOwnBound pins that copyHeader caps the copy at maxHeaderSize itself,
// whatever reader it is handed.
//
// Bytes retained is asserted directly rather than through testutils.MeasureAlloc: the destination is a
// bytes.Buffer, whose doubling growth costs a multiple of what it holds and lands on a different power
// of two depending on the platform. buf.Len() is the same property without that noise.
func TestCopyHeader_appliesItsOwnBound(t *testing.T) {
	const payload = 2*maxHeaderSize + 1

	file := make([]byte, 24, 24+payload)
	binary.LittleEndian.PutUint32(file[0:4], ggufMagicNumber)
	file = append(file, bytes.Repeat([]byte{'x'}, payload)...)

	var buf bytes.Buffer
	require.NoError(t, copyHeader(&buf, bytes.NewReader(file)))
	assert.Equal(t, maxHeaderSize, buf.Len(), "copyHeader must cap the copy at maxHeaderSize")
}
