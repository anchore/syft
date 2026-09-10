# SafeTensors header fixtures

These fixtures are `[8-byte length prefix + JSON header]` captures from
public Docker AI model artifacts on the registry.

`extract_header.go` does a range-GET of the first several MB of the layer,
slices off just `[prefix + JSON header]`, and writes
that to disk.

## Refreshing a fixture

```sh
# from the package root
go run ./testdata/safetensors/extract_header.go \
    docker.io/ai/nomic-embed-text-v2-moe-safetensors:475M \
    ./testdata/safetensors/nomic-embed-475M.header.safetensors
```

The tool prints the layer digest it selected and the number of top-level keys
in the captured header. If you see `header length N does not fit in M fetched
bytes`, raise `fetchBytes` in `extract_header.go` and rerun.

## Notes

- Pick one shard, not the full sharded set. The fixture is meant to exercise
  the per-shard parser; merging across shards has its own tests.
- Don't commit anything larger than ~1 MB. If a model has an unusually large
  header, capture a smaller model instead.
