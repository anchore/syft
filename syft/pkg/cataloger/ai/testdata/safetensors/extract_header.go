// extract_header is a manual fixture tool that captures the real on-disk
// safetensors header from a Docker AI OCI model artifact (a vnd.docker.ai.safetensors
// layer) and writes just [8-byte length prefix + JSON header] to a destination
// file. Tensor data following the header is never downloaded, so the resulting
// fixture is a few KB to a few MB even for multi-GB models.
//
// This file lives under testdata/ so the Go build system ignores it. Run it
// manually when refreshing fixtures:
//
//	go run ./testdata/safetensors/extract_header.go \
//	    docker.io/ai/nomic-embed-text-v2-moe-safetensors:475M \
//	    ./testdata/safetensors/nomic-embed-475M.header.safetensors
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	safetensorsLayerMediaType = "application/vnd.docker.ai.safetensors"
	// 8 MB matches maxHeaderBytes in the OCI model source. Real model headers
	// are well under 1 MB; the extra slack covers outliers.
	fetchBytes = 8 * 1024 * 1024
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <registry-ref> <output-path>\n", os.Args[0])
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(refStr, outPath string) error {
	ctx := context.Background()
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}

	opts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return fmt.Errorf("fetch descriptor: %w", err)
	}

	manifest := &v1.Manifest{}
	if err := json.Unmarshal(desc.Manifest, manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}

	weightLayer := pickWeightLayer(manifest)
	if weightLayer == nil {
		return fmt.Errorf("no %q layer found in %s", safetensorsLayerMediaType, ref)
	}
	fmt.Fprintf(os.Stderr, "selected layer %s (%d bytes on-disk)\n", weightLayer.Digest, weightLayer.Size)

	prefix, err := fetchPrefix(ctx, ref, weightLayer.Digest, opts)
	if err != nil {
		return fmt.Errorf("fetch layer prefix: %w", err)
	}

	header, err := sliceHeader(prefix)
	if err != nil {
		return fmt.Errorf("extract header: %w", err)
	}

	if err := os.WriteFile(outPath, header, 0o644); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(header), outPath)
	return nil
}

// pickWeightLayer returns the first vnd.docker.ai.safetensors layer in the
// manifest, or nil if none exists. For sharded models we deliberately only
// capture one shard: the fixture is meant to exercise the parser, not the
// merge step.
func pickWeightLayer(manifest *v1.Manifest) *v1.Descriptor {
	for i := range manifest.Layers {
		if string(manifest.Layers[i].MediaType) == safetensorsLayerMediaType {
			return &manifest.Layers[i]
		}
	}
	return nil
}

// fetchPrefix range-reads the first fetchBytes of a layer. Closing the reader
// terminates the underlying HTTP body, so we never download the tensor data
// that follows the header.
func fetchPrefix(_ context.Context, ref name.Reference, digest v1.Hash, opts []remote.Option) ([]byte, error) {
	layer, err := remote.Layer(ref.Context().Digest(digest.String()), opts...)
	if err != nil {
		return nil, err
	}
	reader, err := layer.Compressed()
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	buf := make([]byte, fetchBytes)
	n, err := io.ReadFull(reader, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:n], nil
}

// sliceHeader reads the 8-byte little-endian length prefix and returns just
// [prefix + JSON header]. It also probes the JSON to make sure the captured
// fixture is well-formed, so we never commit a half-truncated header.
func sliceHeader(buf []byte) ([]byte, error) {
	if len(buf) < 8 {
		return nil, fmt.Errorf("short read: only %d bytes", len(buf))
	}
	headerLen := binary.LittleEndian.Uint64(buf[:8])
	if headerLen == 0 {
		return nil, fmt.Errorf("header length is zero")
	}
	if headerLen > uint64(len(buf)-8) {
		return nil, fmt.Errorf("header length %d does not fit in %d fetched bytes; increase fetchBytes", headerLen, len(buf))
	}

	out := buf[:8+int(headerLen)]
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(out[8:], &probe); err != nil {
		return nil, fmt.Errorf("captured JSON does not parse: %w", err)
	}
	fmt.Fprintf(os.Stderr, "header parses cleanly: %d top-level keys\n", len(probe))
	return out, nil
}
