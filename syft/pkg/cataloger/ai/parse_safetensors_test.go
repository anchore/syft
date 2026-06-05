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

	"github.com/anchore/syft/syft/artifact"
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

// TestSafeTensorsCataloger is the end-to-end `dir:` scan naming matrix: it walks
// real on-disk directory trees and locks how a model package gets its name at
// every depth a .safetensors file can appear (the scan root `./`, an immediate
// child `./sometensor/`, and a grandchild `./dir/someothertensor/`).
//
// The naming precedence (owned by the merge processor's pickSafeTensorsName) is:
//  1. config.json _name_or_path  (path.Base applied), found beside the model or
//     by walking up parent directories to the scan root
//  2. otherwise the model's immediate parent directory base name
//     → drop (no package) when neither yields a usable name
//
// Every model below is built from the same header bytes, so the header-derived
// metadata (Quantization/Parameters/TensorCount/UserMetadata/MetadataHash) is
// identical across rows and each row stays focused on naming.
func TestSafeTensorsCataloger(t *testing.T) {
	userMeta := map[string]string{"format": "pt"}
	tensors := map[string]safeTensorsEntry{
		"model.embed.weight": {DType: "BF16", Shape: []int64{1000, 16}, DataOffsets: []int64{0, 32000}},
		"model.layer.weight": {DType: "BF16", Shape: []int64{16, 16}, DataOffsets: []int64{32000, 32512}},
	}
	// the dedicated hash test below locks the algorithm; here we only assert the
	// cataloger wires the header hash through to the package metadata.
	wantHash := (&safeTensorsHeader{metadata: userMeta, tensors: tensors}).metadataHash()

	// model writes the shared .safetensors header into dir/<name>.safetensors,
	// creating dir if needed.
	model := func(t *testing.T, dir string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "model.safetensors"), buildSafeTensorsFile(t, userMeta, tensors), 0o644))
	}
	writeFile := func(t *testing.T, path, contents string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	}
	// wantMetadata is the constant header-derived metadata; architecture is the
	// only field that varies (it's enriched from config.json when present).
	wantMetadata := func(architecture string) pkg.SafeTensorsModelInfo {
		return pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			Architecture: architecture,
			Quantization: "BF16",
			Parameters:   "16.26K",
			TensorCount:  2,
			ShardCount:   1,
			UserMetadata: pkg.KeyValues{{Key: "format", Value: "pt"}},
			MetadataHash: wantHash,
		}
	}

	tests := []struct {
		name                  string
		setup                 func(t *testing.T) string
		expectedPackages      []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			// rung 1: config.json _name_or_path (path.Base of "org/Llama-3-8B")
			// wins over the "sometensor" directory fallback; license from README.
			name: "config.json _name_or_path names the model and wins over the directory",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				modelDir := filepath.Join(dir, "sometensor")
				model(t, modelDir)
				writeFile(t, filepath.Join(modelDir, "config.json"),
					`{"architectures":["LlamaForCausalLM"],"torch_dtype":"bfloat16","transformers_version":"4.40.0","_name_or_path":"meta-llama/Llama-3-8B"}`)
				writeFile(t, filepath.Join(modelDir, "README.md"),
					"---\nlicense: Apache-2.0\nbase_model:\n  - meta-llama/Llama-3\n---\n# Llama 3\n")
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name: "Llama-3-8B",
					Type: pkg.ModelPkg,
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromFields("Apache-2.0", "", nil),
					),
					Metadata: wantMetadata("LlamaForCausalLM"),
				},
			},
		},
		{
			// rung 1 via README: with no config.json, the README model card's
			// base_model names the model (path.Base applied), still beating the
			// directory fallback ("readme-named").
			name: "README base_model names the model when there is no config.json",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				modelDir := filepath.Join(dir, "readme-named")
				model(t, modelDir)
				writeFile(t, filepath.Join(modelDir, "README.md"),
					"---\nbase_model:\n  - org/base-model-name\n---\n# Card\n")
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:     "base-model-name",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata(""),
				},
			},
		},
		{
			// rung 2: no config.json at all, so the model is named after its
			// immediate parent directory.
			name: "no config.json falls back to the parent directory name",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				model(t, filepath.Join(dir, "sometensor"))
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:     "sometensor",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata(""),
				},
			},
		},
		{
			// rung 2: config.json exists but carries no _name_or_path (only
			// non-identifying info), so we still fall back to the directory name
			// while enriching architecture from the config.
			name: "config.json without _name_or_path falls back to the parent directory name",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				modelDir := filepath.Join(dir, "sometensor")
				model(t, modelDir)
				writeFile(t, filepath.Join(modelDir, "config.json"),
					`{"architectures":["LlamaForCausalLM"],"torch_dtype":"bfloat16"}`)
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:     "sometensor",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata("LlamaForCausalLM"),
				},
			},
		},
		{
			// rung 2: the fallback is the IMMEDIATE parent ("someothertensor"),
			// not an ancestor ("dir").
			name: "nested model with no config.json is named by its immediate parent directory",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				model(t, filepath.Join(dir, "dir", "someothertensor"))
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:     "someothertensor",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata(""),
				},
			},
		},
		{
			// rung 1 at the scan root: a model directly at `./` is unnameable by
			// the directory fallback (its parent is the degenerate root "."), but
			// a sibling config.json still names it.
			name: "root-level model is named from a root config.json",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				model(t, dir)
				writeFile(t, filepath.Join(dir, "config.json"), `{"_name_or_path":"org/RootModel"}`)
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:     "RootModel",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata(""),
				},
			},
		},
		{
			// drop: a model directly at `./` with no config.json has no usable
			// name — the parent is the degenerate root ".", which yields no
			// directory fallback — so no package is emitted.
			name: "root-level model with no config.json is dropped",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				model(t, dir)
				return dir
			},
			expectedPackages: nil,
		},
		{
			// rung 1 via parent-walk: findDirHFConfig walks up from the model
			// directory, so a config.json in an ancestor names a nested model.
			name: "config.json in an ancestor directory names a nested model",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				model(t, filepath.Join(dir, "dir", "someothertensor"))
				writeFile(t, filepath.Join(dir, "dir", "config.json"), `{"_name_or_path":"org/Ancestor"}`)
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:     "Ancestor",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata(""),
				},
			},
		},
		{
			// grouping: independent models in one scan are grouped by their own
			// parent directory and each named from it.
			name: "sibling models in one scan are each named by their own directory",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				model(t, filepath.Join(dir, "sometensor"))
				model(t, filepath.Join(dir, "dir", "someothertensor"))
				return dir
			},
			expectedPackages: []pkg.Package{
				{
					Name:     "sometensor",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata(""),
				},
				{
					Name:     "someothertensor",
					Type:     pkg.ModelPkg,
					Metadata: wantMetadata(""),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureDir := tt.setup(t)

			pkgtest.NewCatalogTester().
				FromDirectory(t, fixtureDir).
				Expects(tt.expectedPackages, tt.expectedRelationships).
				IgnoreLocationLayer().
				IgnorePackageFields("FoundBy", "Locations").
				TestCataloger(t, NewSafeTensorsCataloger())
		})
	}
}

// TestSafeTensorsCataloger_shardedDirectory covers the primary multi-shard shape:
// several `model-0000N-of-0000M.safetensors` files in one directory. The
// cataloger must group the shards into a single package, sum their tensor counts,
// record the shard count, and roll each shard up into Parts. (The OCI multi-shard
// path is covered separately in TestSafeTensorsMergeProcessor.)
func TestSafeTensorsCataloger_shardedDirectory(t *testing.T) {
	userMeta := map[string]string{"format": "pt"}
	// Two shards with distinct tensors → distinct per-shard metadata hashes, so
	// the merge treats them as separate shards (3 tensors total across 2 shards).
	shardA := map[string]safeTensorsEntry{
		"layers.0.weight": {DType: "BF16", Shape: []int64{10, 10}, DataOffsets: []int64{0, 200}},
	}
	shardB := map[string]safeTensorsEntry{
		"layers.1.weight": {DType: "BF16", Shape: []int64{10, 10}, DataOffsets: []int64{0, 200}},
		"layers.2.weight": {DType: "BF16", Shape: []int64{10, 10}, DataOffsets: []int64{200, 400}},
	}

	dir := t.TempDir()
	modelDir := filepath.Join(dir, "llama-sharded")
	require.NoError(t, os.MkdirAll(modelDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, "model-00001-of-00002.safetensors"),
		buildSafeTensorsFile(t, userMeta, shardA), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, "model-00002-of-00002.safetensors"),
		buildSafeTensorsFile(t, userMeta, shardB), 0o644))

	pkgtest.NewCatalogTester().
		FromDirectory(t, dir).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, _ []artifact.Relationship) {
			require.Len(t, pkgs, 1)
			got := pkgs[0]
			assert.Equal(t, "llama-sharded", got.Name, "a sharded model with no config.json is named by its directory")
			md := got.Metadata.(pkg.SafeTensorsModelInfo)
			assert.Equal(t, 2, md.ShardCount)
			assert.Equal(t, uint64(3), md.TensorCount, "tensor counts are summed across shards")
			assert.Len(t, md.Parts, 2, "each shard is rolled up into Parts")
			assert.Equal(t, "BF16", md.Quantization)
		}).
		TestCataloger(t, NewSafeTensorsCataloger())
}

// TestParseSafeTensorsOCIConfig covers the parser in isolation: it should emit
// a nameless package mirroring the config blob's producer-declared fields, and
// emit nothing for non-safetensors formats so the GGUF cataloger can claim the
// artifact. Naming and license resolution happen in the merge processor and are
// tested separately under TestSafeTensorsMergeProcessor.
func TestParseSafeTensorsOCIConfig(t *testing.T) {
	tests := []struct {
		name             string
		blob             string
		expectedPackages []pkg.Package // nil => parser must emit nothing
	}{
		{
			name: "emits a nameless package with config-blob fields",
			blob: `{"config":{"format":"safetensors","quantization":"Q4_K_M","parameters":"8B","size":"16.00GB","safetensors":{"tensor_count":291}}}`,
			expectedPackages: []pkg.Package{
				{
					// nameless: the merge processor assigns the name and resolves
					// licenses. Config blobs carry no header content, so
					// MetadataHash stays empty.
					Type: pkg.ModelPkg,
					Metadata: pkg.SafeTensorsModelInfo{
						Format:       "safetensors",
						Quantization: "Q4_K_M",
						Parameters:   "8B",
						TotalSize:    "16.00GB",
						TensorCount:  291,
					},
				},
			},
		},
		{
			// non-safetensors formats emit nothing so the GGUF cataloger can claim
			// the artifact.
			name:             "ignores non-safetensors format",
			blob:             `{"config":{"format":"gguf","quantization":"Q4_K_M"}}`,
			expectedPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromString("/config.json", tt.blob).
				Expects(tt.expectedPackages, nil).
				IgnorePackageFields("FoundBy", "Locations").
				TestParser(t, parseSafeTensorsOCIConfig)
		})
	}
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

	t.Run("dir scan: parent directory base name names the group when no config.json is present", func(t *testing.T) {
		// Without a config.json the dir-scan path falls through to the
		// parent directory base name. hugginface style model dir is named after the
		// model, so "/models/tiny-llama/weights.safetensors" → "tiny-llama".
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
		assert.Equal(t, "tiny-llama", out[0].Name, "rung 2: parent directory base name")
	})

	t.Run("dir scan: nested model dirs group and name by immediate parent", func(t *testing.T) {
		top := dirPkg("/namea/1.safetensors", pkg.SafeTensorsModelInfo{
			Format: "safetensors", TensorCount: 1, MetadataHash: "aaaa",
		})
		nested := dirPkg("/namea/nameb/2.safetensors", pkg.SafeTensorsModelInfo{
			Format: "safetensors", TensorCount: 1, MetadataHash: "bbbb",
		})
		resolver := file.NewMockResolverForPaths()
		out, _, err := safeTensorsMergeProcessor(context.Background(), resolver, []pkg.Package{top, nested}, nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 2)
		names := []string{out[0].Name, out[1].Name}
		assert.ElementsMatch(t, []string{"namea", "nameb"}, names)
	})

	t.Run("dir scan: config.json _name_or_path beats the parent directory fallback", func(t *testing.T) {
		// When a sibling config.json carries _name_or_path
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"),
			[]byte(`{"_name_or_path":"org/preferred-name"}`), 0o644))
		stPath := filepath.Join(dir, "weights.safetensors")
		p := dirPkg(stPath, pkg.SafeTensorsModelInfo{
			Format: "safetensors", TensorCount: 1, MetadataHash: "abc",
		})
		resolver := file.NewMockResolverForPaths(filepath.Join(dir, "config.json"))
		out, _, err := safeTensorsMergeProcessor(context.Background(), resolver, []pkg.Package{p}, nil, nil)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "preferred-name", out[0].Name, "rung 1 (config.json) wins over rung 2 (parent dir)")
	})

	t.Run("OCI: dropped when no name source is available", func(t *testing.T) {
		// The vllm-style shape: config-blob package + a weight-layer package,
		// both at virtual path "/", no model.file companions on the resolver
		// AND no image ref. With nothing to derive a name from, the package is
		// dropped
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

	t.Run("OCI: image-ref last segment names the group when config.json is absent", func(t *testing.T) {
		// vllm-style artifact: a repacked model whose embedded config.json has
		// been stripped of _name_or_path.
		configMd := pkg.SafeTensorsModelInfo{
			Format:      "safetensors",
			TensorCount: 290,
			TotalSize:   "723MB",
		}
		shardMd := pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			TensorCount:  290,
			Quantization: "BF16",
			MetadataHash: "deadbeef",
		}
		resolver := file.NewMockResolverForOCIArtifact(
			"docker.io/ai/smollm2-vllm:360M", nil,
		)
		out, _, err := safeTensorsMergeProcessor(
			context.Background(), resolver,
			[]pkg.Package{ociPkg(configMd), ociPkg(shardMd)}, nil, nil,
		)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "smollm2-vllm", out[0].Name, "rung 2: image-ref repository basename")
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

	t.Run("OCI: license layer SPDX comes from choosealicense frontmatter", func(t *testing.T) {
		// The license layer's content carries a choosealicense.com-style YAML
		// frontmatter block. The processor should prefer the cheap spdx-id read
		// over invoking the full license scanner.
		dir := t.TempDir()
		licensePath := filepath.Join(dir, "LICENSE")
		require.NoError(t, os.WriteFile(licensePath, []byte(`---
title: Apache License 2.0
spdx-id: Apache-2.0
---

                                 Apache License
                           Version 2.0, January 2004
`), 0o644))
		hfConfigPath := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(hfConfigPath,
			[]byte(`{"_name_or_path":"org/with-license-fm"}`), 0o644))
		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
			dockerAIModelFileMediaType: {file.NewLocation(hfConfigPath)},
			dockerAILicenseMediaType:   {file.NewLocation(licensePath)},
		})

		configMd := pkg.SafeTensorsModelInfo{Format: "safetensors", TensorCount: 1}
		out, _, err := safeTensorsMergeProcessor(
			context.Background(), resolver,
			[]pkg.Package{ociPkg(configMd)}, nil, nil,
		)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "with-license-fm", out[0].Name)
		assertHasLicense(t, out[0], "Apache-2.0")
	})

	t.Run("OCI: license layer wins over a README model-card license", func(t *testing.T) {
		// When both a dedicated license layer and a README model-card license are
		// present, the producer-curated license layer is authoritative. (If the
		// README won, the resolved license would be MIT and this assertion fails.)
		dir := t.TempDir()
		licensePath := filepath.Join(dir, "LICENSE")
		require.NoError(t, os.WriteFile(licensePath, []byte("---\nspdx-id: Apache-2.0\n---\n"), 0o644))
		readmePath := filepath.Join(dir, "README.md")
		require.NoError(t, os.WriteFile(readmePath,
			[]byte("---\nlicense: MIT\nbase_model:\n  - org/base\n---\n# Card\n"), 0o644))
		configPath := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(configPath, []byte(`{"_name_or_path":"org/precedence-model"}`), 0o644))
		resolver := file.NewMockResolverForMediaTypes(map[string][]file.Location{
			dockerAIModelFileMediaType: {file.NewLocation(configPath), file.NewLocation(readmePath)},
			dockerAILicenseMediaType:   {file.NewLocation(licensePath)},
		})

		configMd := pkg.SafeTensorsModelInfo{Format: "safetensors", TensorCount: 1}
		out, _, err := safeTensorsMergeProcessor(
			context.Background(), resolver,
			[]pkg.Package{ociPkg(configMd)}, nil, nil,
		)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "precedence-model", out[0].Name)
		assertHasLicense(t, out[0], "Apache-2.0")
	})

	t.Run("passes through upstream error", func(t *testing.T) {
		sentinel := assert.AnError
		p := dirPkg("/models/x/y.safetensors", pkg.SafeTensorsModelInfo{Format: "safetensors", MetadataHash: "h"})
		out, _, err := safeTensorsMergeProcessor(context.Background(), nil, []pkg.Package{p}, nil, sentinel)
		assert.Equal(t, sentinel, err)
		assert.Equal(t, []pkg.Package{p}, out)
	})
}

// TestSafeTensorsNamingPrecedence codifies pickSafeTensorsName's two-rung
// precedence chain. Each case sets the inputs that should activate one rung
// (or neither, asserting the drop path).
//
// Precedence (highest → lowest):
//  1. config.json _name_or_path  (path.Base applied; both dir-scan and OCI)
//  2. fallback name — OCI image-ref last segment, or dir-scan parent directory
//     base name (the merge processor computes the right one per group)
//     → drop (empty name) when nothing matches
func TestSafeTensorsNamingPrecedence(t *testing.T) {
	tests := []struct {
		name         string
		nameOrPath   string
		fallbackName string
		want         string
	}{
		// rung 1
		{
			name:         "rung 1: _name_or_path beats the fallback",
			nameOrPath:   "org/MyModel",
			fallbackName: "fallback-name",
			want:         "MyModel",
		},
		{
			name:       "rung 1: applies path.Base to the raw value",
			nameOrPath: "very/deep/checkpoint/path/leaf-model",
			want:       "leaf-model",
		},
		{
			name:       "rung 1: bare name without slashes is preserved",
			nameOrPath: "OciModel",
			want:       "OciModel",
		},

		// rung 2
		{
			name:         "rung 2: OCI image-ref last segment used when _name_or_path is empty",
			fallbackName: "smollm2-vllm",
			want:         "smollm2-vllm",
		},
		{
			name:         "rung 2: dir-scan parent directory name used when _name_or_path is empty",
			fallbackName: "tiny-llama",
			want:         "tiny-llama",
		},

		// drops
		{
			name: "drop: both rungs empty",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickSafeTensorsName(tt.nameOrPath, tt.fallbackName)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestSafeTensorsDirName covers the directory-scan fallback name derivation,
// including the degenerate roots that must yield no name.
func TestSafeTensorsDirName(t *testing.T) {
	tests := []struct {
		groupKey string
		want     string
	}{
		{groupKey: "/models/tiny-llama", want: "tiny-llama"},
		{groupKey: "/namea", want: "namea"},
		{groupKey: "/namea/nameb", want: "nameb"},
		{groupKey: "/", want: ""},
		{groupKey: ".", want: ""},
		{groupKey: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.groupKey, func(t *testing.T) {
			assert.Equal(t, tt.want, safeTensorsDirName(tt.groupKey))
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
		// nameless: the merge processor assigns the name. Parameters is the
		// summed element count of the two tensors (1024*16 + 16*16 = 16640).
		expected := []pkg.Package{
			{
				Type: pkg.ModelPkg,
				Metadata: pkg.SafeTensorsModelInfo{
					Format:       "safetensors",
					Parameters:   "16.64K",
					Quantization: "BF16",
					TensorCount:  2,
					UserMetadata: wantUserMetadata,
					MetadataHash: wantHash,
				},
			},
		}
		pkgtest.NewCatalogTester().
			FromString("/", string(blob)).
			Expects(expected, nil).
			IgnorePackageFields("FoundBy", "Locations").
			TestParser(t, parseSafeTensorsOCILayer)
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
	// nameless before the merge processor runs. The fixture is immutable on disk;
	// the locked field values (notably MetadataHash) guard against the header
	// parser silently breaking on real-world content shape — if MetadataHash
	// changes, either the hash algorithm or the canonicalization changed, both of
	// which callers may rely on for cross-source identity.
	expected := []pkg.Package{
		{
			Type: pkg.ModelPkg,
			Metadata: pkg.SafeTensorsModelInfo{
				Format:       "safetensors",
				Parameters:   "475.29M",
				Quantization: "F32", // every tensor in the captured shard is F32
				TensorCount:  148,   // nomic-embed-v2-moe 475M ships 148 tensor entries in this shard
				UserMetadata: pkg.KeyValues{{Key: "format", Value: "pt"}},
				MetadataHash: "051a14e686673dea",
			},
		},
	}

	pkgtest.NewCatalogTester().
		FromFile(t, filepath.Join("testdata", "safetensors", "nomic-embed-475M.header.safetensors")).
		Expects(expected, nil).
		IgnorePackageFields("FoundBy", "Locations").
		TestParser(t, parseSafeTensorsOCILayer)
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
	zeroLength := make([]byte, 8) // length prefix of 0

	truncatedBody := make([]byte, 8)
	binary.LittleEndian.PutUint64(truncatedBody, 100) // claims 100 bytes but supplies none

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		assert  func(t *testing.T, h *safeTensorsHeader)
	}{
		{
			name: "valid header",
			data: buildSafeTensorsFile(t, map[string]string{"format": "pt"}, map[string]safeTensorsEntry{
				"w": {DType: "F32", Shape: []int64{2, 2}, DataOffsets: []int64{0, 16}},
			}),
			assert: func(t *testing.T, h *safeTensorsHeader) {
				assert.Len(t, h.tensors, 1)
				assert.Equal(t, "pt", h.metadata["format"])
			},
		},
		{
			name:    "zero-length header",
			data:    zeroLength,
			wantErr: true,
		},
		{
			name:    "truncated body",
			data:    truncatedBody,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := readSafeTensorsHeader(bytes.NewReader(tt.data))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			tt.assert(t, h)
		})
	}
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
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "already canonical BF16", in: "BF16", want: "BF16"},
		{name: "float16 alias", in: "float16", want: "F16"},
		{name: "FP32 alias", in: "FP32", want: "F32"},
		{name: "int8 alias", in: "int8", want: "I8"},
		{name: "U8 passthrough", in: "U8", want: "U8"},
		{name: "bool", in: "bool", want: "BOOL"},
		{name: "unknown value uppercased", in: "weird", want: "WEIRD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeDType(tt.in))
		})
	}
}

func TestFormatParameterCount(t *testing.T) {
	tests := []struct {
		name string
		in   uint64
		want string
	}{
		{name: "raw count under 1K", in: 512, want: "512"},
		{name: "thousands", in: 16256, want: "16.26K"},
		{name: "billions", in: 2_680_000_000, want: "2.68B"},
		{name: "millions", in: 35_000_000, want: "35.00M"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatParameterCount(tt.in))
		})
	}
}

func TestParseFrontmatter(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantNil       bool
		wantLicense   string
		wantBaseModel []string
	}{
		{
			name:          "list base_model",
			input:         "---\nlicense: mit\nbase_model:\n  - org/Model\n---\nbody",
			wantLicense:   "mit",
			wantBaseModel: []string{"org/Model"},
		},
		{
			name:          "scalar base_model",
			input:         "---\nlicense: apache-2.0\nbase_model: org/Model\n---\n",
			wantLicense:   "apache-2.0",
			wantBaseModel: []string{"org/Model"},
		},
		{
			name:        "leading BOM",
			input:       "\xef\xbb\xbf---\nlicense: mit\n---\n",
			wantLicense: "mit",
		},
		{
			name:    "no frontmatter",
			input:   "# just a heading\n",
			wantNil: true,
		},
		{
			name:    "unterminated frontmatter",
			input:   "---\nlicense: mit\n",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := parseFrontmatter([]byte(tt.input))
			if tt.wantNil {
				assert.Nil(t, fm)
				return
			}
			require.NotNil(t, fm)
			assert.Equal(t, tt.wantLicense, fm.License)
			if tt.wantBaseModel != nil {
				assert.Equal(t, tt.wantBaseModel, fm.BaseModel)
			}
		})
	}
}

// TestParseLicenseFrontmatter covers the choosealicense.com-style YAML
// frontmatter Docker Model Runner uses for its license layers. Only spdx-id
// is consumed; everything else in the block is ignored.
func TestParseLicenseFrontmatter(t *testing.T) {
	// The Apache-2.0 case is the exact frontmatter shape from
	// https://github.com/github/choosealicense.com/blob/gh-pages/_licenses/apache-2.0.txt
	// Docker AI license layers ship a near-identical block.
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name: "Apache-2.0 (the canonical choosealicense.com shape)",
			input: `---
title: Apache License 2.0
spdx-id: Apache-2.0
redirect_from: /licenses/apache/
featured: true
hidden: false

description: A permissive license whose main conditions require preservation of copyright and license notices.

how: Create a text file (typically named LICENSE or LICENSE.txt) in the root of your source code and copy the text of the license into the file.

using:
  Kubernetes: https://github.com/kubernetes/kubernetes/blob/master/LICENSE
  PDF.js: https://github.com/mozilla/pdf.js/blob/master/LICENSE
  Swift: https://github.com/apple/swift/blob/main/LICENSE.txt

permissions:
  - commercial-use
  - modifications
  - distribution
  - patent-use
  - private-use

conditions:
  - include-copyright
  - document-changes

limitations:
  - trademark-use
  - liability
  - warranty

---

                                 Apache License
                           Version 2.0, January 2004
`,
			want: "Apache-2.0",
		},
		{
			name:  "MIT with BOM prefix",
			input: "\xef\xbb\xbf---\ntitle: MIT License\nspdx-id: MIT\n---\nThe MIT License...\n",
			want:  "MIT",
		},
		{
			name:  "frontmatter without spdx-id falls through (returns empty)",
			input: "---\ntitle: Something\ndescription: no spdx-id here\n---\nbody\n",
			want:  "",
		},
		{
			name:  "plain license text without any frontmatter",
			input: "                                 Apache License\n                           Version 2.0, January 2004\n",
			want:  "",
		},
		{
			name:  "unterminated frontmatter block",
			input: "---\nspdx-id: MIT\n(never closes)\n",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseLicenseFrontmatter([]byte(tt.input)))
		})
	}
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

	tests := []struct {
		name      string
		mediaType string
		want      bool
	}{
		// the known, verified schema versions are consumed
		{name: "known schema v0.1 is consumed", mediaType: "application/vnd.docker.ai.model.config.v0.1+json", want: true},
		{name: "known schema v0.2 is consumed", mediaType: "application/vnd.docker.ai.model.config.v0.2+json", want: true},
		// unknown/future schema versions are intentionally NOT consumed, to avoid
		// silently ingesting a potentially breaking config change
		{name: "unknown schema v0.3 is rejected", mediaType: "application/vnd.docker.ai.model.config.v0.3+json", want: false},
		{name: "far-future schema v9.9 is rejected", mediaType: "application/vnd.docker.ai.model.config.v9.9+json", want: false},
		// sibling layer media types are not matched either
		{name: "sibling model.file layer is not matched", mediaType: "application/vnd.docker.ai.model.file", want: false},
		{name: "sibling gguf layer is not matched", mediaType: "application/vnd.docker.ai.gguf.v3", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, supported(tt.mediaType))
		})
	}
}
