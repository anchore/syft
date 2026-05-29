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

// TestParseSafeTensorsOCIConfig covers the parser in isolation: it should emit
// a nameless package mirroring the config blob's producer-declared fields, and
// emit nothing for non-safetensors formats so the GGUF cataloger can claim the
// artifact. Naming and license resolution happen in the merge processor and are
// tested separately under TestSafeTensorsMergeProcessor.
func TestParseSafeTensorsOCIConfig(t *testing.T) {
	t.Run("emits a nameless package with config-blob fields", func(t *testing.T) {
		blob := []byte(`{"config":{"format":"safetensors","quantization":"Q4_K_M","parameters":"8B","size":"16.00GB","safetensors":{"tensor_count":291}}}`)

		pkgs, _, err := parseSafeTensorsOCIConfig(context.Background(), nil, nil, configReader(blob))
		require.NoError(t, err)
		require.Len(t, pkgs, 1)

		p := pkgs[0]
		assert.Empty(t, p.Name, "config-blob parser must emit nameless; the merge processor names it")
		assert.Empty(t, p.Licenses.ToSlice(), "license resolution belongs to the merge processor")
		md := p.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, "safetensors", md.Format)
		assert.Equal(t, "Q4_K_M", md.Quantization)
		assert.Equal(t, "8B", md.Parameters)
		assert.Equal(t, "16.00GB", md.TotalSize)
		assert.Equal(t, uint64(291), md.TensorCount)
		assert.Empty(t, md.MetadataHash, "config blobs have no header content to hash")
	})

	t.Run("ignores non-safetensors format", func(t *testing.T) {
		ggufBlob := []byte(`{"config":{"format":"gguf","quantization":"Q4_K_M"}}`)
		pkgs, _, err := parseSafeTensorsOCIConfig(context.Background(), nil, nil, configReader(ggufBlob))
		require.NoError(t, err)
		assert.Empty(t, pkgs)
	})
}

// TestSafeTensorsMergeProcessor exercises the merge processor directly with
// synthetic input. The full-cataloger integration tests cover the realistic
// happy paths; this focuses on grouping, the naming precedence chain, the
// drop-when-unnameable rule, and cross-shard rollup.
func TestSafeTensorsMergeProcessor(t *testing.T) {
	dirPkg := func(realPath string, md pkg.SafeTensorsModelInfo) pkg.Package {
		return pkg.Package{
			Type:     pkg.ModelPkg,
			Metadata: md,
			Locations: file.NewLocationSet(
				file.NewLocation(realPath).
					WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		}
	}
	ociPkg := func(md pkg.SafeTensorsModelInfo) pkg.Package {
		return pkg.Package{
			Type:     pkg.ModelPkg,
			Metadata: md,
			Locations: file.NewLocationSet(
				file.NewLocation("/").
					WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		}
	}

	t.Run("dir scan: parent-dir fallback names a bare safetensors with no siblings", func(t *testing.T) {
		// case #1: model.safetensors in /models/tiny-llama/ with no config.json
		// or README. The processor cannot derive a producer name and Architecture
		// is empty, so it lands on the parent-dir rung.
		p := dirPkg("/models/tiny-llama/weights.safetensors", pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			TensorCount:  4,
			Quantization: "BF16",
			MetadataHash: "abc",
		})
		resolver := file.NewMockResolverForPaths() // no config.json / README available
		out, _, err := safeTensorsMergeProcessor(context.Background(), resolver, []pkg.Package{p}, nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "tiny-llama", out[0].Name)
	})

	t.Run("dir scan: parent-dir fallback rescues a metadata-only header", func(t *testing.T) {
		// case #3: header carries only __metadata__, no tensors. Parameters and
		// Architecture are both empty, so Arch-Parameters can't fire either —
		// the parent-dir fallback is the only thing that names the package.
		p := dirPkg("/scan/edge/headeronly/model.safetensors", pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			MetadataHash: "xyz",
			UserMetadata: pkg.KeyValues{{Key: "producer", Value: "stgen"}},
		})
		resolver := file.NewMockResolverForPaths()
		out, _, err := safeTensorsMergeProcessor(context.Background(), resolver, []pkg.Package{p}, nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "headeronly", out[0].Name)
	})

	t.Run("dir scan: Architecture-Parameters synthetic wins over parent-dir", func(t *testing.T) {
		// Architecture and Parameters are both populated → synthetic wins over
		// the parent-dir fallback. _name_or_path is not available (no sibling
		// config.json mock).
		p := dirPkg("/models/tiny/weights.safetensors", pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			Architecture: "LlamaForCausalLM",
			Parameters:   "2.68B",
			TensorCount:  4,
			MetadataHash: "abc",
		})
		resolver := file.NewMockResolverForPaths()
		out, _, err := safeTensorsMergeProcessor(context.Background(), resolver, []pkg.Package{p}, nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "LlamaForCausalLM-2.68B", out[0].Name)
	})

	t.Run("OCI: dropped when no name source is available", func(t *testing.T) {
		// The vllm-style shape: config-blob package + a weight-layer package,
		// both at virtual path "/", no model.file companions on the resolver.
		// With nothing to derive a name from, the group is dropped (no opaque
		// fallback / no parent-dir option for OCI).
		configMd := pkg.SafeTensorsModelInfo{
			Format:      "safetensors",
			TensorCount: 5,
			TotalSize:   "1GB",
		}
		shardMd := pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			TensorCount:  5,
			Quantization: "BF16",
			MetadataHash: "deadbeef",
		}
		resolver := file.NewMockResolverForMediaTypes(nil)
		out, _, err := safeTensorsMergeProcessor(
			context.Background(), resolver,
			[]pkg.Package{ociPkg(configMd), ociPkg(shardMd)}, nil, nil,
		)
		require.NoError(t, err)
		assert.Empty(t, out, "OCI group with no naming source must be dropped")
	})

	t.Run("OCI: merges config + shard and names from companion config.json", func(t *testing.T) {
		// Write a single model.file companion blob containing HF config.json so
		// the processor can derive _name_or_path and Architecture from it.
		dir := t.TempDir()
		hfConfigPath := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(hfConfigPath,
			[]byte(`{"architectures":["Qwen3ForCausalLM"],"torch_dtype":"bfloat16","_name_or_path":"org/qwen-tiny"}`), 0o644))
		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
			dockerAIModelFileMediaType: {file.NewLocation(hfConfigPath)},
		})

		configMd := pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			Quantization: "Q4_K_M", // raw producer-declared value
			Parameters:   "8B",
			TotalSize:    "16.00GB",
			TensorCount:  291,
		}
		shardMd := pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			TensorCount:  100, // per-shard count — must NOT be summed onto the aggregate's 291
			Quantization: "BF16",
			MetadataHash: "deadbeef",
			UserMetadata: pkg.KeyValues{{Key: "format", Value: "pt"}},
		}
		out, _, err := safeTensorsMergeProcessor(
			context.Background(), resolver,
			[]pkg.Package{ociPkg(configMd), ociPkg(shardMd)}, nil, nil,
		)
		require.NoError(t, err)
		require.Len(t, out, 1)

		got := out[0]
		assert.Equal(t, "qwen-tiny", got.Name, "name comes from path.Base(_name_or_path)")
		md := got.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, uint64(291), md.TensorCount, "aggregate TensorCount must win — never double-count by summing the shard")
		assert.Equal(t, "16.00GB", md.TotalSize)
		assert.Equal(t, "8B", md.Parameters)
		assert.Equal(t, "Qwen3ForCausalLM", md.Architecture, "Architecture enriched from companion config.json")
		assert.Equal(t, "bfloat16", md.TorchDtype)
		assert.Equal(t, "Q4_K_M", md.Quantization, "aggregate Quantization wins over shard's normalized dtype when both present")
		assert.Equal(t, "deadbeef", md.MetadataHash, "single-shard rollup is the lone shard's hash")
		assert.Equal(t, pkg.KeyValues{{Key: "format", Value: "pt"}}, md.UserMetadata)
		assert.Nil(t, md.Parts, "single-shard groups skip Parts; the outer view already exposes everything")
	})

	t.Run("OCI: multi-shard rollup hashes are stable and sorted", func(t *testing.T) {
		dir := t.TempDir()
		hfConfigPath := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(hfConfigPath,
			[]byte(`{"architectures":["X"],"_name_or_path":"org/multi"}`), 0o644))
		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
			dockerAIModelFileMediaType: {file.NewLocation(hfConfigPath)},
		})

		configMd := pkg.SafeTensorsModelInfo{Format: "safetensors", TensorCount: 9, TotalSize: "3GB"}
		shard := func(hash string, cnt uint64) pkg.SafeTensorsModelInfo {
			return pkg.SafeTensorsModelInfo{Format: "safetensors", TensorCount: cnt, Quantization: "BF16", MetadataHash: hash}
		}
		in := []pkg.Package{
			ociPkg(configMd),
			ociPkg(shard("cccc", 3)),
			ociPkg(shard("aaaa", 3)),
			ociPkg(shard("bbbb", 3)),
		}
		out1, _, err := safeTensorsMergeProcessor(context.Background(), resolver, in, nil, nil)
		require.NoError(t, err)
		require.Len(t, out1, 1)
		md1 := out1[0].Metadata.(pkg.SafeTensorsModelInfo)
		require.Len(t, md1.Parts, 3)
		// Parts deterministically sorted by MetadataHash.
		assert.Equal(t,
			[]string{"aaaa", "bbbb", "cccc"},
			[]string{md1.Parts[0].MetadataHash, md1.Parts[1].MetadataHash, md1.Parts[2].MetadataHash},
		)
		// Rollup hash is stable across input ordering.
		shuffled := []pkg.Package{ociPkg(shard("bbbb", 3)), ociPkg(configMd), ociPkg(shard("aaaa", 3)), ociPkg(shard("cccc", 3))}
		out2, _, err := safeTensorsMergeProcessor(context.Background(), resolver, shuffled, nil, nil)
		require.NoError(t, err)
		md2 := out2[0].Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, md1.MetadataHash, md2.MetadataHash, "rollup hash must not depend on input order")
	})

	t.Run("passes through upstream error", func(t *testing.T) {
		sentinel := assert.AnError
		p := dirPkg("/models/x/y.safetensors", pkg.SafeTensorsModelInfo{Format: "safetensors", MetadataHash: "h"})
		out, _, err := safeTensorsMergeProcessor(context.Background(), nil, []pkg.Package{p}, nil, sentinel)
		assert.Equal(t, sentinel, err)
		assert.Equal(t, []pkg.Package{p}, out)
	})
}

// TestSafeTensorsNamingPrecedence codifies pickSafeTensorsName's documented
// precedence chain. Each case sets exactly the inputs that should activate one
// rung and asserts the expected outcome — including the drop case when every
// rung is unavailable.
//
// Precedence (highest → lowest):
//  1. config.json _name_or_path  (path.Base applied)
//  2. OCI manifest title         (follow-up; covered today by an empty-string input)
//  3. Architecture + Parameters  (both must be non-empty)
//  4. parent directory           (dir-scan only; OCI groups skip this rung)
//  → drop (empty name) when nothing matches
func TestSafeTensorsNamingPrecedence(t *testing.T) {
	const dirGroup = "/scan/parent-name"

	cases := []struct {
		name       string
		groupKey   string
		nameOrPath string
		arch       string
		params     string
		want       string
	}{
		// rung 1
		{
			name:       "rung 1: _name_or_path beats Arch+Params and parent-dir",
			groupKey:   dirGroup,
			nameOrPath: "org/MyModel",
			arch:       "LlamaForCausalLM",
			params:     "7B",
			want:       "MyModel",
		},
		{
			name:       "rung 1: applies path.Base to the raw value",
			groupKey:   dirGroup,
			nameOrPath: "very/deep/checkpoint/path/leaf-model",
			want:       "leaf-model",
		},
		{
			name:       "rung 1: works for OCI groups too",
			groupKey:   ociGroupKey,
			nameOrPath: "org/OciModel",
			want:       "OciModel",
		},

		// rung 3
		{
			name:     "rung 3: Arch+Params wins when no _name_or_path",
			groupKey: dirGroup,
			arch:     "LlamaForCausalLM",
			params:   "7B",
			want:     "LlamaForCausalLM-7B",
		},
		{
			name:     "rung 3: works for OCI groups (the only non-drop rung when no manifest title)",
			groupKey: ociGroupKey,
			arch:     "Qwen3ForCausalLM",
			params:   "2.66B",
			want:     "Qwen3ForCausalLM-2.66B",
		},
		{
			name:     "rung 3 NOT taken when only Architecture is set: falls through to parent-dir",
			groupKey: dirGroup,
			arch:     "LlamaForCausalLM",
			want:     "parent-name",
		},
		{
			name:     "rung 3 NOT taken when only Parameters is set: falls through to parent-dir",
			groupKey: dirGroup,
			params:   "7B",
			want:     "parent-name",
		},

		// rung 4
		{
			name:     "rung 4: parent-dir when no other rung populated",
			groupKey: dirGroup,
			want:     "parent-name",
		},
		{
			name:     "rung 4 skipped for OCI groups: no usable parent path",
			groupKey: ociGroupKey,
			want:     "",
		},

		// drops
		{
			name:     "drop: dir group at filesystem root",
			groupKey: "/",
			want:     "",
		},
		{
			name:     "drop: dir group with empty parent",
			groupKey: ".",
			want:     "",
		},
		{
			name:     "drop: OCI group with nothing",
			groupKey: ociGroupKey,
			want:     "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged := pkg.Package{
				Type: pkg.ModelPkg,
				Metadata: pkg.SafeTensorsModelInfo{
					Architecture: tc.arch,
					Parameters:   tc.params,
				},
			}
			got := pickSafeTensorsName(merged, tc.groupKey, tc.nameOrPath)
			assert.Equal(t, tc.want, got)
		})
	}
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

	t.Run("merged via processor: aggregate fields preserved, hash lifted from single shard", func(t *testing.T) {
		// Synthesize the OCI single-shard shape: a config-blob-derived nameless
		// package + the weight-layer parser's nameless package (both at virtual
		// path "/"). With a companion HF config.json on the resolver to provide
		// _name_or_path, the merge processor produces a single named model.
		dir := t.TempDir()
		hfConfigPath := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(hfConfigPath,
			[]byte(`{"architectures":["Qwen3ForCausalLM"],"_name_or_path":"org/qwen-test"}`), 0o644))
		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
			dockerAIModelFileMediaType: {file.NewLocation(hfConfigPath)},
		})

		configPkg := pkg.Package{
			Type: pkg.ModelPkg,
			Metadata: pkg.SafeTensorsModelInfo{
				Format:       "safetensors",
				Parameters:   "2.68B",
				TotalSize:    "5.00GB",
				Quantization: "Q4_K_M", // raw producer string
				TensorCount:  9999,
			},
			Locations: file.NewLocationSet(
				file.NewLocation("/").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		}
		reader := file.NewLocationReadCloser(
			file.NewLocation("/").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			io.NopCloser(bytes.NewReader(blob)),
		)
		layerPkgs, _, err := parseSafeTensorsOCILayer(context.Background(), nil, nil, reader)
		require.NoError(t, err)
		require.Len(t, layerPkgs, 1)

		out, _, err := safeTensorsMergeProcessor(
			context.Background(), resolver,
			append([]pkg.Package{configPkg}, layerPkgs...), nil, nil,
		)
		require.NoError(t, err)
		require.Len(t, out, 1)

		got := out[0]
		assert.Equal(t, "qwen-test", got.Name, "name comes from the companion config.json _name_or_path")
		md := got.Metadata.(pkg.SafeTensorsModelInfo)
		// Aggregate-declared fields win for totals; per-shard count must NOT be
		// summed into the aggregate.
		assert.Equal(t, uint64(9999), md.TensorCount)
		assert.Equal(t, "5.00GB", md.TotalSize)
		assert.Equal(t, "2.68B", md.Parameters)
		// Aggregate Quantization wins when set; shard's normalized dtype is the
		// fallback (not exercised here because the config had Q4_K_M).
		assert.Equal(t, "Q4_K_M", md.Quantization)
		// Architecture comes from companion HF config.json enrichment.
		assert.Equal(t, "Qwen3ForCausalLM", md.Architecture)
		// Single-shard groups skip Parts; the rollup hash is the lone shard's hash.
		assert.Nil(t, md.Parts)
		assert.Equal(t, wantHash, md.MetadataHash)
		assert.Equal(t, wantUserMetadata, md.UserMetadata)
		assert.Equal(t, 1, md.ShardCount)
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
