package internal

import (
	"fmt"

	"github.com/opencontainers/go-digest"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

// DeriveImageID derives an artifact ID from the given image metadata. The order of data precedence is:
//  1. prefer a digest of the raw container image manifest
//  2. if no manifest digest is available, calculate a chain ID from the image layer metadata
//  3. if no layer metadata is available, use the user input string
//
// in all cases, if an alias is provided, it is additionally considered in the ID calculation. This allows for the
// same image to be scanned multiple times with different aliases and be considered logically different.
func DeriveImageID(alias source.Alias, metadata source.ImageMetadata) artifact.ID {
	var input string

	if len(metadata.RawManifest) > 0 {
		input = digest.Canonical.FromBytes(metadata.RawManifest).String()
	} else {
		// calculate chain ID for image sources where manifestDigest is not available
		// https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
		input = calculateChainID(metadata.Layers)
		if input == "" {
			// TODO what happens here if image has no layers?
			// is this case possible?
			input = digest.Canonical.FromString(metadata.UserInput).String()
		}
	}

	if !alias.IsEmpty() {
		// if the user provided an alias, we want to consider that in the artifact ID. This way if the user
		// scans the same item but is considered to be logically different, then ID will express that.
		aliasStr := fmt.Sprintf(":%s@%s", alias.Name, alias.Version)
		input = digest.Canonical.FromString(input + aliasStr).String()
	}

	return ArtifactIDFromDigest(input)
}

// https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
func calculateChainID(lm []source.LayerMetadata) string {
	if len(lm) < 1 {
		return ""
	}

	// DiffID(L0) = digest of layer 0
	// https://github.com/anchore/stereoscope/blob/1b1b744a919964f38d14e1416fb3f25221b761ce/pkg/image/layer_metadata.go#L19-L32
	chainID := lm[0].Digest
	id := chain(chainID, lm[1:])

	return id
}

func chain(chainID string, layers []source.LayerMetadata) string {
	if len(layers) < 1 {
		return chainID
	}

	chainID = digest.Canonical.FromString(layers[0].Digest + " " + chainID).String()
	return chain(chainID, layers[1:])
}
