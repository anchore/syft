package ai

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

// buildSafeTensorsFile builds the on-disk bytes of a .safetensors file: an
// 8-byte little-endian header length followed by the JSON header. Tensor data
// is omitted because the parser only reads the header.
func buildSafeTensorsFile(t *testing.T, metadata map[string]string, tensors map[string]safeTensorsEntry) []byte {
	t.Helper()
	raw := map[string]any{}
	if metadata != nil {
		raw["__metadata__"] = metadata
	}
	for name, entry := range tensors {
		raw[name] = entry
	}
	body, err := json.Marshal(raw)
	require.NoError(t, err)

	out := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint64(out[:8], uint64(len(body)))
	copy(out[8:], body)
	return out
}

func TestSafeTensorsCataloger_singleFile(t *testing.T) {
	userMeta := map[string]string{"format": "pt"}
	tensors := map[string]safeTensorsEntry{
		"model.embed.weight": {DType: "BF16", Shape: []int64{1000, 16}, DataOffsets: []int64{0, 32000}},
		"model.layer.weight": {DType: "BF16", Shape: []int64{16, 16}, DataOffsets: []int64{32000, 32512}},
	}
	// the dedicated hash test below locks the algorithm; here we only assert the
	// cataloger wires the header hash through to the package metadata.
	wantHash := (&safeTensorsHeader{metadata: userMeta, tensors: tensors}).metadataHash()

	dir := t.TempDir()
	modelDir := filepath.Join(dir, "models")
	require.NoError(t, os.MkdirAll(modelDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, "model.safetensors"), buildSafeTensorsFile(t, userMeta, tensors), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, "config.json"),
		[]byte(`{"architectures":["LlamaForCausalLM"],"torch_dtype":"bfloat16","transformers_version":"4.40.0","_name_or_path":"meta-llama/Llama-3-8B"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, "README.md"),
		[]byte("---\nlicense: Apache-2.0\nbase_model:\n  - meta-llama/Llama-3\n---\n# Llama 3\n"), 0o644))

	expected := []pkg.Package{
		{
			Name: "Llama-3-8B",
			Type: pkg.ModelPkg,
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromFields("Apache-2.0", "", nil),
			),
			Metadata: pkg.SafeTensorsModelInfo{
				Format:              "safetensors",
				Architecture:        "LlamaForCausalLM",
				Quantization:        "BF16",
				Parameters:          "16.26K",
				TensorCount:         2,
				TorchDtype:          "bfloat16",
				TransformersVersion: "4.40.0",
				ShardCount:          1,
				UserMetadata:        pkg.KeyValues{{Key: "format", Value: "pt"}},
				MetadataHash:        wantHash,
			},
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		Expects(expected, nil).
		IgnoreLocationLayer().
		IgnorePackageFields("FoundBy", "Locations").
		TestCataloger(t, NewSafeTensorsCataloger())
}

func TestSafeTensorsCataloger_shardedIndex(t *testing.T) {
	dir := t.TempDir()
	modelDir := filepath.Join(dir, "my-model")
	require.NoError(t, os.MkdirAll(modelDir, 0o755))
	index := `{
		"metadata": {"total_size": 16000000000},
		"weight_map": {
			"layer.0.weight": "model-00001-of-00002.safetensors",
			"layer.1.weight": "model-00001-of-00002.safetensors",
			"layer.2.weight": "model-00002-of-00002.safetensors"
		}
	}`
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, "model.safetensors.index.json"), []byte(index), 0o644))

	expected := []pkg.Package{
		{
			Name:     "my-model",
			Type:     pkg.ModelPkg,
			Licenses: pkg.NewLicenseSet(),
			Metadata: pkg.SafeTensorsModelInfo{
				Format:      "safetensors",
				TensorCount: 3,
				ShardCount:  2,
				TotalSize:   "14.90GB",
			},
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		Expects(expected, nil).
		IgnoreLocationLayer().
		IgnorePackageFields("FoundBy", "Locations").
		TestCataloger(t, NewSafeTensorsCataloger())
}

func TestParseSafeTensorsOCIConfig(t *testing.T) {
	configBlob := []byte(`{"config":{"format":"safetensors","quantization":"Q4_K_M","parameters":"8B","size":"16.00GB","safetensors":{"tensor_count":291}}}`)

	t.Run("enriches from companion layers", func(t *testing.T) {
		dir := t.TempDir()
		readmePath := filepath.Join(dir, "README.md")
		require.NoError(t, os.WriteFile(readmePath,
			[]byte("---\nlicense: mit\nbase_model:\n  - org/My-Model\n---\n# card\n"), 0o644))
		hfConfigPath := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(hfConfigPath,
			[]byte(`{"architectures":["Qwen3ForCausalLM"],"torch_dtype":"bfloat16"}`), 0o644))

		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
			dockerAIModelFileMediaType: {file.NewLocation(readmePath), file.NewLocation(hfConfigPath)},
		})

		pkgs, _, err := parseSafeTensorsOCIConfig(context.Background(), resolver, nil, configReader(configBlob))
		require.NoError(t, err)
		require.Len(t, pkgs, 1)

		p := pkgs[0]
		assert.Equal(t, "My-Model", p.Name)
		assert.Equal(t, pkg.ModelPkg, p.Type)
		assertHasLicense(t, p, "mit")

		md := p.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, "safetensors", md.Format)
		assert.Equal(t, "Qwen3ForCausalLM", md.Architecture)
		assert.Equal(t, "bfloat16", md.TorchDtype)
		assert.Equal(t, "Q4_K_M", md.Quantization)
		assert.Equal(t, "8B", md.Parameters)
		assert.Equal(t, "16.00GB", md.TotalSize)
		assert.Equal(t, uint64(291), md.TensorCount)
	})

	t.Run("falls back to license layer", func(t *testing.T) {
		dir := t.TempDir()
		readmePath := filepath.Join(dir, "README.md")
		require.NoError(t, os.WriteFile(readmePath,
			[]byte("---\nbase_model:\n  - org/My-Model\n---\n"), 0o644))
		licensePath := filepath.Join(dir, "LICENSE")
		require.NoError(t, os.WriteFile(licensePath,
			[]byte("                                 Apache License\n                           Version 2.0, January 2004\n"), 0o644))

		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
			dockerAIModelFileMediaType: {file.NewLocation(readmePath)},
			dockerAILicenseMediaType:   {file.NewLocation(licensePath)},
		})

		pkgs, _, err := parseSafeTensorsOCIConfig(context.Background(), resolver, nil, configReader(configBlob))
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		assertHasLicense(t, pkgs[0], "Apache-2.0")
	})

	t.Run("config _name_or_path wins over README base_model regardless of layer order", func(t *testing.T) {
		dir := t.TempDir()
		readmePath := filepath.Join(dir, "README.md")
		require.NoError(t, os.WriteFile(readmePath, []byte("---\nbase_model:\n  - org/Readme-Name\n---\n"), 0o644))
		hfConfigPath := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(hfConfigPath, []byte(`{"_name_or_path":"org/Config-Name"}`), 0o644))

		// both layer orderings must yield the same (config-derived) name
		orderings := [][]file.Location{
			{file.NewLocation(readmePath), file.NewLocation(hfConfigPath)},
			{file.NewLocation(hfConfigPath), file.NewLocation(readmePath)},
		}
		for _, locs := range orderings {
			resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
				dockerAIModelFileMediaType: locs,
			})
			pkgs, _, err := parseSafeTensorsOCIConfig(context.Background(), resolver, nil, configReader(configBlob))
			require.NoError(t, err)
			require.Len(t, pkgs, 1)
			assert.Equal(t, "Config-Name", pkgs[0].Name)
		}
	})

	t.Run("falls back to default name when none derivable", func(t *testing.T) {
		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{})

		pkgs, _, err := parseSafeTensorsOCIConfig(context.Background(), resolver, nil, configReader(configBlob))
		require.NoError(t, err)
		require.Len(t, pkgs, 1)
		assert.Equal(t, "safetensors-model", pkgs[0].Name, "model must still be emitted, not dropped")
	})

	t.Run("ignores non-safetensors format", func(t *testing.T) {
		ggufBlob := []byte(`{"config":{"format":"gguf","quantization":"Q4_K_M"}}`)
		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{})

		pkgs, _, err := parseSafeTensorsOCIConfig(context.Background(), resolver, nil, configReader(ggufBlob))
		require.NoError(t, err)
		assert.Empty(t, pkgs)
	})
}

func TestSafeTensorsMergeProcessor(t *testing.T) {
	named := pkg.Package{Name: "model-a", Type: pkg.ModelPkg, Metadata: pkg.SafeTensorsModelInfo{Format: "safetensors", MetadataHash: "aaaa"}}
	nameless := pkg.Package{Name: "", Type: pkg.ModelPkg, Metadata: pkg.SafeTensorsModelInfo{Format: "safetensors", MetadataHash: "bbbb"}}

	t.Run("merges nameless into named parts", func(t *testing.T) {
		out, _, err := safeTensorsMergeProcessor([]pkg.Package{named, nameless}, nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "model-a", out[0].Name)
		md := out[0].Metadata.(pkg.SafeTensorsModelInfo)
		require.Len(t, md.Parts, 1)
		assert.Empty(t, md.Parts[0].MetadataHash, "nameless part hash should be cleared")
		assert.Equal(t, 1, md.ShardCount)
	})

	t.Run("sets ShardCount from absorbed parts", func(t *testing.T) {
		// Three nameless layer packages absorbed into one named config-derived package.
		parts := []pkg.Package{
			{Name: "", Type: pkg.ModelPkg, Metadata: pkg.SafeTensorsModelInfo{Format: "safetensors", MetadataHash: "cccc"}},
			{Name: "", Type: pkg.ModelPkg, Metadata: pkg.SafeTensorsModelInfo{Format: "safetensors", MetadataHash: "aaaa"}},
			{Name: "", Type: pkg.ModelPkg, Metadata: pkg.SafeTensorsModelInfo{Format: "safetensors", MetadataHash: "bbbb"}},
		}
		out, _, err := safeTensorsMergeProcessor(append([]pkg.Package{named}, parts...), nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 1)
		md := out[0].Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, 3, md.ShardCount)
		require.Len(t, md.Parts, 3)
		// Hashes are cleared on absorbed parts, so sort order is deterministic ("" repeated).
		// The non-deterministic resolver order should not surface here either way.
		for _, p := range md.Parts {
			assert.Empty(t, p.MetadataHash)
		}
	})

	t.Run("drops result when no named package", func(t *testing.T) {
		out, _, err := safeTensorsMergeProcessor([]pkg.Package{nameless}, nil, nil)
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("passes through upstream error", func(t *testing.T) {
		sentinel := assert.AnError
		out, _, err := safeTensorsMergeProcessor([]pkg.Package{named}, nil, sentinel)
		assert.Equal(t, sentinel, err)
		assert.Len(t, out, 1)
	})
}

func TestParseSafeTensorsOCILayer(t *testing.T) {
	tensors := map[string]safeTensorsEntry{
		"layer.0.weight": {DType: "BF16", Shape: []int64{1024, 16}, DataOffsets: []int64{0, 32768}},
		"layer.1.weight": {DType: "BF16", Shape: []int64{16, 16}, DataOffsets: []int64{32768, 33280}},
	}
	userMeta := map[string]string{"format": "pt"}
	wantUserMetadata := pkg.KeyValues{{Key: "format", Value: "pt"}}
	blob := buildSafeTensorsFile(t, userMeta, tensors)
	wantHash := (&safeTensorsHeader{metadata: userMeta, tensors: tensors}).metadataHash()

	t.Run("emits a nameless package with header-derived metadata", func(t *testing.T) {
		reader := file.NewLocationReadCloser(file.NewLocation("/"), io.NopCloser(bytes.NewReader(blob)))
		pkgs, _, err := parseSafeTensorsOCILayer(context.Background(), nil, nil, reader)
		require.NoError(t, err)
		require.Len(t, pkgs, 1)

		p := pkgs[0]
		assert.Empty(t, p.Name, "weight-layer parser must emit nameless; the merge processor names it")
		md := p.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, "safetensors", md.Format)
		assert.Equal(t, uint64(2), md.TensorCount)
		assert.Equal(t, "BF16", md.Quantization)
		assert.Equal(t, wantUserMetadata, md.UserMetadata)
		assert.Equal(t, wantHash, md.MetadataHash)
	})

	t.Run("merges with config-derived named package and lifts ShardCount", func(t *testing.T) {
		// Synthesize what the OCI scan would produce: one config-derived named
		// package + one weight-layer derived nameless package. Run them through
		// the merge processor and assert the result looks like a complete model.
		configMd := pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			Architecture: "Qwen3ForCausalLM",
			Parameters:   "2.68B",
			TotalSize:    "5.00GB",
			Quantization: "Q4_K_M", // raw producer string
		}
		named := pkg.Package{Name: "qwen", Type: pkg.ModelPkg, Metadata: configMd}

		reader := file.NewLocationReadCloser(file.NewLocation("/"), io.NopCloser(bytes.NewReader(blob)))
		layerPkgs, _, err := parseSafeTensorsOCILayer(context.Background(), nil, nil, reader)
		require.NoError(t, err)
		require.Len(t, layerPkgs, 1)

		out, _, err := safeTensorsMergeProcessor(append([]pkg.Package{named}, layerPkgs...), nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 1)

		md := out[0].Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, 1, md.ShardCount, "merge processor should set ShardCount from absorbed parts")
		// Producer-declared top-level fields are preserved.
		assert.Equal(t, "Qwen3ForCausalLM", md.Architecture)
		assert.Equal(t, "Q4_K_M", md.Quantization)
		// The header-derived hash lives in Parts so callers can compare against a dir scan.
		require.Len(t, md.Parts, 1)
		// MetadataHash is cleared on absorbed parts by the existing merge processor.
		// What survives is the rest of the per-shard metadata (UserMetadata, TensorCount,
		// header-derived Quantization). Confirm those are intact.
		assert.Equal(t, wantUserMetadata, md.Parts[0].UserMetadata)
		assert.Equal(t, uint64(2), md.Parts[0].TensorCount)
		assert.Equal(t, "BF16", md.Parts[0].Quantization, "part keeps the normalized header dtype")
	})
}

// TestParseSafeTensorsOCILayer_realFixture grounds the OCI layer parser
// against a real `[prefix + JSON header]` captured from a public Docker AI
// model artifact (docker.io/ai/nomic-embed-text-v2-moe-safetensors:475M).
// The fixture and the tool that produced it live in
// testdata/safetensors/; see the README there to refresh.
//
// Locking in the field values guards against changes to the header parser
// silently breaking on real-world content shape.
func TestParseSafeTensorsOCILayer_realFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "safetensors", "nomic-embed-475M.header.safetensors"))
	require.NoError(t, err)
	require.Greater(t, len(data), 8, "fixture must include the 8-byte length prefix")

	reader := file.NewLocationReadCloser(file.NewLocation("/"), io.NopCloser(bytes.NewReader(data)))
	pkgs, _, err := parseSafeTensorsOCILayer(context.Background(), nil, nil, reader)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Empty(t, pkgs[0].Name, "weight-layer packages are nameless before the merge processor runs")

	md := pkgs[0].Metadata.(pkg.SafeTensorsModelInfo)
	assert.Equal(t, "safetensors", md.Format)
	assert.Equal(t, uint64(148), md.TensorCount, "nomic-embed-v2-moe 475M ships 148 tensor entries in this shard")
	assert.Equal(t, "F32", md.Quantization, "every tensor in the captured shard is F32")
	assert.Equal(t, "475.29M", md.Parameters)
	assert.Equal(t, pkg.KeyValues{{Key: "format", Value: "pt"}}, md.UserMetadata)
	// MetadataHash is locked to the exact value the parser produces for this
	// captured input. The fixture is immutable on disk; if this value changes
	// either the hash algorithm or the canonicalization changed, both of which
	// callers may rely on for cross-source identity.
	assert.Equal(t, "051a14e686673dea", md.MetadataHash)
}

func TestSafeTensorsCrossSourceHashParity(t *testing.T) {
	// Same content, two paths: a directory scan via parseSafeTensorsFile, and an
	// OCI weight-layer scan via parseSafeTensorsOCILayer. The MetadataHash of
	// the dir-scan package must equal the per-shard hash captured before the
	// merge processor absorbs it. This is the convergence point that lets a
	// caller correlate the two source types.
	tensors := map[string]safeTensorsEntry{
		"a.weight": {DType: "BF16", Shape: []int64{8, 8}, DataOffsets: []int64{0, 128}},
		"b.weight": {DType: "BF16", Shape: []int64{4, 4}, DataOffsets: []int64{128, 160}},
	}
	userMeta := map[string]string{"format": "pt", "producer": "test"}
	blob := buildSafeTensorsFile(t, userMeta, tensors)

	// dir-scan path
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "model.safetensors"), blob, 0o644))
	dirReader := func() file.LocationReadCloser {
		f, err := os.Open(filepath.Join(dir, "model.safetensors"))
		require.NoError(t, err)
		return file.NewLocationReadCloser(file.NewLocation(filepath.Join(dir, "model.safetensors")), f)
	}()
	dirPkgs, _, err := parseSafeTensorsFile(context.Background(), nil, nil, dirReader)
	require.NoError(t, err)
	require.Len(t, dirPkgs, 1)
	dirHash := dirPkgs[0].Metadata.(pkg.SafeTensorsModelInfo).MetadataHash
	require.NotEmpty(t, dirHash)

	// OCI weight-layer path
	ociReader := file.NewLocationReadCloser(file.NewLocation("/"), io.NopCloser(bytes.NewReader(blob)))
	ociPkgs, _, err := parseSafeTensorsOCILayer(context.Background(), nil, nil, ociReader)
	require.NoError(t, err)
	require.Len(t, ociPkgs, 1)
	ociHash := ociPkgs[0].Metadata.(pkg.SafeTensorsModelInfo).MetadataHash

	assert.Equal(t, dirHash, ociHash, "same content via dir scan and OCI weight-layer scan must hash equal")
}

func configReader(blob []byte) file.LocationReadCloser {
	return file.NewLocationReadCloser(file.NewLocation("/config.json"), io.NopCloser(bytes.NewReader(blob)))
}

func assertHasLicense(t *testing.T, p pkg.Package, value string) {
	t.Helper()
	for _, l := range p.Licenses.ToSlice() {
		if l.Value == value {
			return
		}
	}
	t.Errorf("expected license %q, got %+v", value, p.Licenses.ToSlice())
}

func TestReadSafeTensorsHeader(t *testing.T) {
	t.Run("valid header", func(t *testing.T) {
		data := buildSafeTensorsFile(t, map[string]string{"format": "pt"}, map[string]safeTensorsEntry{
			"w": {DType: "F32", Shape: []int64{2, 2}, DataOffsets: []int64{0, 16}},
		})
		h, n, err := readSafeTensorsHeader(bytes.NewReader(data))
		require.NoError(t, err)
		assert.Equal(t, uint64(len(data)-8), n)
		assert.Len(t, h.tensors, 1)
		assert.Equal(t, "pt", h.metadata["format"])
	})

	t.Run("zero-length header", func(t *testing.T) {
		var buf [8]byte // length prefix of 0
		_, _, err := readSafeTensorsHeader(bytes.NewReader(buf[:]))
		require.Error(t, err)
	})

	t.Run("truncated body", func(t *testing.T) {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], 100) // claims 100 bytes but supplies none
		_, _, err := readSafeTensorsHeader(bytes.NewReader(buf[:]))
		require.Error(t, err)
	})
}

func TestSafeTensorsHeader_metadataHash(t *testing.T) {
	base := &safeTensorsHeader{
		metadata: map[string]string{"format": "pt"},
		tensors: map[string]safeTensorsEntry{
			"a.weight": {DType: "F32", Shape: []int64{2, 2}, DataOffsets: []int64{0, 16}},
			"b.weight": {DType: "F16", Shape: []int64{4}, DataOffsets: []int64{16, 24}},
		},
	}

	// deterministic across calls and independent of map insertion order
	reordered := &safeTensorsHeader{
		metadata: map[string]string{"format": "pt"},
		tensors: map[string]safeTensorsEntry{
			"b.weight": {DType: "F16", Shape: []int64{4}, DataOffsets: []int64{16, 24}},
			"a.weight": {DType: "F32", Shape: []int64{2, 2}, DataOffsets: []int64{0, 16}},
		},
	}
	assert.Equal(t, base.metadataHash(), reordered.metadataHash())
	assert.Len(t, base.metadataHash(), 16)

	// changing a tensor changes the hash
	changed := &safeTensorsHeader{
		metadata: base.metadata,
		tensors: map[string]safeTensorsEntry{
			"a.weight": {DType: "F32", Shape: []int64{2, 3}, DataOffsets: []int64{0, 24}},
			"b.weight": {DType: "F16", Shape: []int64{4}, DataOffsets: []int64{24, 32}},
		},
	}
	assert.NotEqual(t, base.metadataHash(), changed.metadataHash())

	// changing __metadata__ changes the hash
	differentMeta := &safeTensorsHeader{metadata: map[string]string{"format": "np"}, tensors: base.tensors}
	assert.NotEqual(t, base.metadataHash(), differentMeta.metadataHash())
}

func TestSafeTensorsHeader_parameterCountAndDType(t *testing.T) {
	h := &safeTensorsHeader{tensors: map[string]safeTensorsEntry{
		"big":    {DType: "BF16", Shape: []int64{1000, 16}},
		"small":  {DType: "F32", Shape: []int64{16, 16}},
		"scalar": {DType: "F32", Shape: []int64{}}, // empty shape contributes 1
	}}
	assert.Equal(t, uint64(1000*16+16*16+1), h.parameterCount())
	assert.Equal(t, "BF16", h.dominantDType())
}

func TestNormalizeDType(t *testing.T) {
	cases := map[string]string{
		"BF16":    "BF16",
		"float16": "F16",
		"FP32":    "F32",
		"int8":    "I8",
		"U8":      "U8",
		"bool":    "BOOL",
		"weird":   "WEIRD",
	}
	for in, want := range cases {
		assert.Equalf(t, want, normalizeDType(in), "normalizeDType(%q)", in)
	}
}

func TestFormatParameterCount(t *testing.T) {
	cases := map[uint64]string{
		512:           "512",
		16256:         "16.26K",
		2_680_000_000: "2.68B",
		35_000_000:    "35.00M",
	}
	for in, want := range cases {
		assert.Equalf(t, want, formatParameterCount(in), "formatParameterCount(%d)", in)
	}
}

func TestFormatByteSize(t *testing.T) {
	cases := map[string]string{
		"16000000000": "14.90GB",
		"2048":        "2.00KB",
		"500":         "500B",
		"71.90GB":     "71.90GB", // non-numeric passes through unchanged
		"":            "",
	}
	for in, want := range cases {
		assert.Equalf(t, want, formatByteSize(in), "formatByteSize(%q)", in)
	}
}

func TestParseFrontmatter(t *testing.T) {
	t.Run("list base_model", func(t *testing.T) {
		fm := parseFrontmatter([]byte("---\nlicense: mit\nbase_model:\n  - org/Model\n---\nbody"))
		require.NotNil(t, fm)
		assert.Equal(t, "mit", fm.License)
		assert.Equal(t, []string{"org/Model"}, fm.BaseModel)
	})

	t.Run("scalar base_model", func(t *testing.T) {
		fm := parseFrontmatter([]byte("---\nlicense: apache-2.0\nbase_model: org/Model\n---\n"))
		require.NotNil(t, fm)
		assert.Equal(t, "apache-2.0", fm.License)
		assert.Equal(t, []string{"org/Model"}, fm.BaseModel)
	})

	t.Run("leading BOM", func(t *testing.T) {
		fm := parseFrontmatter([]byte("\xef\xbb\xbf---\nlicense: mit\n---\n"))
		require.NotNil(t, fm)
		assert.Equal(t, "mit", fm.License)
	})

	t.Run("no frontmatter", func(t *testing.T) {
		assert.Nil(t, parseFrontmatter([]byte("# just a heading\n")))
	})

	t.Run("unterminated frontmatter", func(t *testing.T) {
		assert.Nil(t, parseFrontmatter([]byte("---\nlicense: mit\n")))
	})
}

func TestModelNameFromPath(t *testing.T) {
	assert.Equal(t, "foo", modelNameFromPath("/models/foo/model.safetensors"))
	assert.Equal(t, "weights", modelNameFromPath("weights.safetensors"))
	assert.Equal(t, "my-model", modelNameFromIndexPath("/models/my-model/model.safetensors.index.json"))
	assert.Equal(t, "safetensors-model", modelNameFromIndexPath("model.safetensors.index.json"))
}

func TestDockerAIModelConfigMediaTypes(t *testing.T) {
	// supported mirrors how the resolver matches: filepath.Match each registered
	// media type against a layer's media type.
	supported := func(mt string) bool {
		for _, p := range dockerAIModelConfigMediaTypes {
			if ok, err := filepath.Match(p, mt); err == nil && ok {
				return true
			}
		}
		return false
	}
	// the known, verified schema versions are consumed
	assert.True(t, supported("application/vnd.docker.ai.model.config.v0.1+json"))
	assert.True(t, supported("application/vnd.docker.ai.model.config.v0.2+json"))
	// unknown/future schema versions are intentionally NOT consumed, to avoid
	// silently ingesting a potentially breaking config change
	assert.False(t, supported("application/vnd.docker.ai.model.config.v0.3+json"))
	assert.False(t, supported("application/vnd.docker.ai.model.config.v9.9+json"))
	// sibling layer media types are not matched either
	assert.False(t, supported("application/vnd.docker.ai.model.file"))
	assert.False(t, supported("application/vnd.docker.ai.gguf.v3"))
}
