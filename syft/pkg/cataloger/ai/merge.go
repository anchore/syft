package ai

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// mergeSafeTensorsGroup folds a group's per-member metadata into a single package.
func mergeSafeTensorsGroup(members []pkg.Package) pkg.Package {
	locSet := unionLocations(members)
	aggregates, shards := bucketSafeTensorsMembers(members)

	merged := pkg.SafeTensorsModelInfo{Format: "safetensors"}
	mergeAggregatesInto(&merged, aggregates)
	shardTensorTotal, hashes := mergeShardsInto(&merged, shards)

	// Keep merged UserMetadata globally key-sorted so the SBOM is stable
	sort.Slice(merged.UserMetadata, func(i, j int) bool {
		return merged.UserMetadata[i].Key < merged.UserMetadata[j].Key
	})

	if merged.TensorCount == 0 {
		merged.TensorCount = shardTensorTotal
	}
	if merged.ShardCount == 0 {
		if len(shards) > 0 {
			merged.ShardCount = len(shards)
		} else {
			merged.ShardCount = 1
		}
	}
	merged.MetadataHash = rollupHash(hashes)

	// Parts only carry value for multi-shard models; for a single shard the
	// outer view already exposes every per-shard field.
	if len(shards) > 1 {
		parts := append([]pkg.SafeTensorsModelInfo(nil), shards...)
		sort.Slice(parts, func(i, j int) bool {
			return parts[i].MetadataHash < parts[j].MetadataHash
		})
		merged.Parts = parts
	}

	return pkg.Package{
		Locations: locSet,
		Type:      pkg.ModelPkg,
		Metadata:  merged,
	}
}

func mergeAggregatesInto(merged *pkg.SafeTensorsModelInfo, aggregates []pkg.SafeTensorsModelInfo) {
	for _, a := range aggregates {
		if merged.TensorCount == 0 {
			merged.TensorCount = a.TensorCount
		}
		firstNonEmpty(&merged.Parameters, a.Parameters)
		firstNonEmpty(&merged.TotalSize, a.TotalSize)
		firstNonEmpty(&merged.Quantization, a.Quantization)
	}
}

// mergeShardsInto folds the per-shard header metadata into merged, returning
// the summed shard TensorCount and the list of non-empty per-shard hashes for
// the rollup. Shards carry only the content-derived fields (Quantization,
// Parameters, UserMetadata), so those are the only fields folded in here.
func mergeShardsInto(merged *pkg.SafeTensorsModelInfo, shards []pkg.SafeTensorsModelInfo) (shardTensorTotal uint64, hashes []string) {
	seenKV := map[string]bool{}
	for _, s := range shards {
		shardTensorTotal += s.TensorCount
		firstNonEmpty(&merged.Quantization, s.Quantization)
		firstNonEmpty(&merged.Parameters, s.Parameters)
		for _, kv := range s.UserMetadata {
			if seenKV[kv.Key] {
				continue
			}
			seenKV[kv.Key] = true
			merged.UserMetadata = append(merged.UserMetadata, kv)
		}
		if s.MetadataHash != "" {
			hashes = append(hashes, s.MetadataHash)
		}
	}
	return shardTensorTotal, hashes
}

func firstNonEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

// unionLocations gathers every location from every member into a single set.
func unionLocations(members []pkg.Package) file.LocationSet {
	out := file.NewLocationSet()
	for _, m := range members {
		for _, l := range m.Locations.ToSlice() {
			out.Add(l)
		}
	}
	return out
}

// bucketSafeTensorsMembers splits group members into aggregate-flavored entries
// (no MetadataHash — Docker AI config blob or sharded index) and shard-flavored
// entries (carry a content-derived MetadataHash from a header parser).
func bucketSafeTensorsMembers(members []pkg.Package) (aggregates, shards []pkg.SafeTensorsModelInfo) {
	for _, m := range members {
		md, ok := m.Metadata.(pkg.SafeTensorsModelInfo)
		if !ok {
			continue
		}
		if md.MetadataHash != "" {
			shards = append(shards, md)
			continue
		}
		aggregates = append(aggregates, md)
	}
	return aggregates, shards
}

func rollupHash(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	if len(hashes) == 1 {
		return hashes[0]
	}
	sorted := append([]string(nil), hashes...)
	sort.Strings(sorted)
	return fmt.Sprintf("%016x", xxhash.Sum64String(strings.Join(sorted, "|")))
}
