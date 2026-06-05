package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// stPkg builds a model package carrying the given metadata, with each path
// recorded as a primary-evidence location.
func stPkg(md pkg.SafeTensorsModelInfo, paths ...string) pkg.Package {
	locs := make([]file.Location, 0, len(paths))
	for _, p := range paths {
		locs = append(locs, file.NewLocation(p).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	}
	return pkg.Package{Type: pkg.ModelPkg, Metadata: md, Locations: file.NewLocationSet(locs...)}
}

// shardMeta is a content-derived shard entry: it carries a MetadataHash, which is
// what marks a group member as a shard (vs. a hash-less aggregate config blob).
func shardMeta(hash string, tensorCount uint64) pkg.SafeTensorsModelInfo {
	return pkg.SafeTensorsModelInfo{
		Format:       "safetensors",
		TensorCount:  tensorCount,
		Quantization: "BF16",
		Parameters:   "1.00K",
		MetadataHash: hash,
	}
}

// TestMergeSafeTensorsGroup exercises the rollup contract directly (the cataloger
// tests cover it only as a side effect of the merge processor). It locks how a
// group's per-member metadata folds into one package: tensor-count summing,
// aggregate-over-shard field precedence, UserMetadata dedup + sorting, Parts
// rollup, ShardCount derivation, and the content MetadataHash rollup.
func TestMergeSafeTensorsGroup(t *testing.T) {
	t.Run("single shard: hash passes through, ShardCount 1, no Parts", func(t *testing.T) {
		out := mergeSafeTensorsGroup([]pkg.Package{stPkg(shardMeta("aaaa", 5), "/m/a.safetensors")})

		md := out.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, pkg.ModelPkg, out.Type)
		assert.Equal(t, 1, md.ShardCount)
		assert.Equal(t, uint64(5), md.TensorCount)
		assert.Equal(t, "aaaa", md.MetadataHash, "a single shard's hash passes through unchanged")
		assert.Nil(t, md.Parts, "single-shard models do not populate Parts")
	})

	t.Run("multi-shard: tensors summed, Parts sorted by hash, rollup is order-independent", func(t *testing.T) {
		in := []pkg.Package{
			stPkg(shardMeta("cccc", 3), "/m/c.safetensors"),
			stPkg(shardMeta("aaaa", 3), "/m/a.safetensors"),
			stPkg(shardMeta("bbbb", 3), "/m/b.safetensors"),
		}
		out := mergeSafeTensorsGroup(in)

		md := out.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, 3, md.ShardCount)
		assert.Equal(t, uint64(9), md.TensorCount, "tensor counts are summed across shards")
		require.Len(t, md.Parts, 3)
		assert.Equal(t,
			[]string{"aaaa", "bbbb", "cccc"},
			[]string{md.Parts[0].MetadataHash, md.Parts[1].MetadataHash, md.Parts[2].MetadataHash},
			"Parts are sorted by metadata hash",
		)
		assert.Equal(t, rollupHash([]string{"aaaa", "bbbb", "cccc"}), md.MetadataHash)

		// the rollup hash must not depend on the order members arrive in
		shuffled := []pkg.Package{
			stPkg(shardMeta("bbbb", 3), "/m/b.safetensors"),
			stPkg(shardMeta("cccc", 3), "/m/c.safetensors"),
			stPkg(shardMeta("aaaa", 3), "/m/a.safetensors"),
		}
		out2 := mergeSafeTensorsGroup(shuffled)
		assert.Equal(t, md.MetadataHash, out2.Metadata.(pkg.SafeTensorsModelInfo).MetadataHash)
	})

	t.Run("aggregate fields win over shard-derived fields", func(t *testing.T) {
		// an aggregate (OCI config blob) carries no MetadataHash but declares the
		// authoritative totals.
		aggregate := pkg.SafeTensorsModelInfo{
			Format:       "safetensors",
			TensorCount:  999,
			TotalSize:    "5.00GB",
			Parameters:   "2.68B",
			Quantization: "Q4_K_M",
		}
		in := []pkg.Package{
			stPkg(aggregate, "/"),
			stPkg(shardMeta("aaaa", 3), "/"),
			stPkg(shardMeta("bbbb", 3), "/"),
		}
		out := mergeSafeTensorsGroup(in)

		md := out.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, uint64(999), md.TensorCount, "aggregate TensorCount is authoritative; shard counts are not summed in")
		assert.Equal(t, "5.00GB", md.TotalSize)
		assert.Equal(t, "2.68B", md.Parameters)
		assert.Equal(t, "Q4_K_M", md.Quantization, "aggregate quantization wins over the shard dtype")
		assert.Equal(t, 2, md.ShardCount, "ShardCount comes from the number of shards, not the aggregate")
		assert.Equal(t, rollupHash([]string{"aaaa", "bbbb"}), md.MetadataHash, "the content hash still rolls up the shard hashes")
	})

	t.Run("aggregate-only group: ShardCount 1, empty hash, no Parts", func(t *testing.T) {
		aggregate := pkg.SafeTensorsModelInfo{Format: "safetensors", TensorCount: 42, TotalSize: "1.00GB"}
		out := mergeSafeTensorsGroup([]pkg.Package{stPkg(aggregate, "/")})

		md := out.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, uint64(42), md.TensorCount)
		assert.Equal(t, 1, md.ShardCount, "a group with no shards still reports a single shard")
		assert.Equal(t, "", md.MetadataHash, "there are no shard hashes to roll up")
		assert.Nil(t, md.Parts)
	})

	t.Run("UserMetadata: keys merged and sorted, first value wins on conflict", func(t *testing.T) {
		// keys are intentionally unsorted within each shard so the assertion proves
		// the merge re-sorts globally; "format" appears in both shards so dedup
		// precedence (first wins) is exercised too.
		s1 := shardMeta("aaaa", 1)
		s1.UserMetadata = pkg.KeyValues{{Key: "format", Value: "pt"}, {Key: "author", Value: "alice"}}
		s2 := shardMeta("bbbb", 1)
		s2.UserMetadata = pkg.KeyValues{{Key: "format", Value: "gguf"}, {Key: "license", Value: "mit"}}

		out := mergeSafeTensorsGroup([]pkg.Package{stPkg(s1, "/m/a.safetensors"), stPkg(s2, "/m/b.safetensors")})

		md := out.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, pkg.KeyValues{
			{Key: "author", Value: "alice"},
			{Key: "format", Value: "pt"}, // first shard's value wins over s2's "gguf"
			{Key: "license", Value: "mit"},
		}, md.UserMetadata)
	})

	t.Run("members without safetensors metadata are ignored in the rollup", func(t *testing.T) {
		notST := pkg.Package{
			Type:      pkg.ModelPkg,
			Metadata:  pkg.GGUFFileHeader{},
			Locations: file.NewLocationSet(file.NewLocation("/m/x.gguf")),
		}
		out := mergeSafeTensorsGroup([]pkg.Package{stPkg(shardMeta("aaaa", 2), "/m/a.safetensors"), notST})

		md := out.Metadata.(pkg.SafeTensorsModelInfo)
		assert.Equal(t, uint64(2), md.TensorCount, "only the safetensors shard contributes")
		assert.Equal(t, 1, md.ShardCount)
		assert.Equal(t, "aaaa", md.MetadataHash)
	})
}

// TestRollupHash locks the cross-source content-fingerprint rollup: empty input
// yields no hash, a lone shard's hash passes through unchanged (so a single-shard
// model fingerprints identically across directory and OCI sources), and multiple
// shards fold into one order-independent digest.
func TestRollupHash(t *testing.T) {
	assert.Equal(t, "", rollupHash(nil), "no hashes → empty")
	assert.Equal(t, "solo", rollupHash([]string{"solo"}), "a single hash passes through unchanged")

	ab := rollupHash([]string{"a", "b"})
	ba := rollupHash([]string{"b", "a"})
	assert.Equal(t, ab, ba, "the rollup is independent of input order")
	assert.Len(t, ab, 16, "a multi-hash rollup is a 16-char xxhash")
	assert.NotEqual(t, "a", ab)
	assert.NotEqual(t, "b", ab)
}
