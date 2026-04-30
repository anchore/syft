package ocimodelsource

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/anchore/stereoscope/pkg/image"
)

// errNotModelArtifact is returned when a reference does not point to a model artifact.
var errNotModelArtifact = errors.New("not an OCI model artifact")

const (
	// Model artifact media types as per Docker's OCI artifacts for AI model packaging
	// Reference: https://www.docker.com/blog/oci-artifacts-for-ai-model-packaging/
	modelConfigMediaTypePrefix = "application/vnd.docker.ai.model.config."
	ggufLayerMediaType         = "application/vnd.docker.ai.gguf.v3"
	safetensorsLayerMediaType  = "application/vnd.docker.ai.safetensors"

	// Companion metadata layers packaged alongside the weight tensors.
	// model.file covers README.md / config.json / tokenizer.json / generation_config.json.
	modelFileMediaType = "application/vnd.docker.ai.model.file"
	licenseMediaType   = "application/vnd.docker.ai.license"

	// Weight format labels surfaced on modelArtifact.Format.
	modelFormatGGUF        = "gguf"
	modelFormatSafeTensors = "safetensors"

	// Maximum bytes to read/return for weight-layer headers (GGUF + safetensors).
	maxHeaderBytes = 8 * 1024 * 1024 // 8 MB
	// Maximum bytes to fetch for a companion metadata layer (README, config.json, license).
	// These blobs are small by convention; cap well below a safetensors header.
	maxCompanionBytes = 4 * 1024 * 1024 // 4 MB
)

// registryClient handles OCI registry interactions for model artifacts.
type registryClient struct {
	options []remote.Option
}

// newRegistryClient creates a new registry client with authentication from RegistryOptions.
func newRegistryClient(registryOpts *image.RegistryOptions) *registryClient {
	opts := buildRemoteOptions(registryOpts)

	return &registryClient{
		options: opts,
	}
}

// buildRemoteOptions converts stereoscope RegistryOptions to go-containerregistry remote.Options.
func buildRemoteOptions(registryOpts *image.RegistryOptions) []remote.Option {
	var opts []remote.Option

	if registryOpts == nil {
		return opts
	}

	// Build authenticator
	authenticator := buildAuthenticator(registryOpts)
	opts = append(opts, remote.WithAuth(authenticator))

	// Handle TLS settings
	if registryOpts.InsecureSkipTLSVerify {
		if transport, ok := remote.DefaultTransport.(*http.Transport); ok {
			transport = transport.Clone()
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{
					MinVersion: tls.VersionTLS12,
				}
			}
			transport.TLSClientConfig.InsecureSkipVerify = true //#nosec G402 -- user explicitly requested insecure TLS
			opts = append(opts, remote.WithTransport(transport))
		}
	}

	// Handle insecure HTTP
	if registryOpts.InsecureUseHTTP {
		opts = append(opts, remote.WithTransport(http.DefaultTransport))
	}

	return opts
}

// buildAuthenticator creates an authn.Authenticator from RegistryOptions.
func buildAuthenticator(registryOpts *image.RegistryOptions) authn.Authenticator {
	// If credentials are provided, use them
	if len(registryOpts.Credentials) > 0 {
		// Use the first credential set (we could enhance this to match by authority)
		cred := registryOpts.Credentials[0]

		if cred.Token != "" {
			return &authn.Bearer{Token: cred.Token}
		}

		if cred.Username != "" || cred.Password != "" {
			return &authn.Basic{
				Username: cred.Username,
				Password: cred.Password,
			}
		}
	}

	// Fall back to anonymous authenticator
	return authn.Anonymous
}

// modelArtifact represents a parsed OCI model artifact.
type modelArtifact struct {
	Reference      name.Reference
	Manifest       *v1.Manifest
	Config         *v1.ConfigFile
	RawManifest    []byte
	RawConfig      []byte
	ManifestDigest string

	// Format identifies the weight storage format advertised by the manifest's
	// layer media types. Empty means no recognized weight layers were found.
	Format string

	// GGUFLayers are descriptors for layers carrying GGUF-format weights.
	// We fetch the first few MB of each to read the header.
	GGUFLayers []v1.Descriptor

	// SafeTensorsLayers are descriptors for layers carrying SafeTensors-format weights.
	// For safetensors we do NOT fetch these layers — the model-config blob already
	// contains the aggregate metadata we need — but we record them here for counting
	// and for future per-shard parsing.
	SafeTensorsLayers []v1.Descriptor

	// CompanionLayers are non-weight layers (README, config.json, license) that
	// we do fetch (in full, given their small size) so companion-file parsing
	// in the safetensors cataloger can find them via media type.
	CompanionLayers []v1.Descriptor
}

func (c *registryClient) fetchModelArtifact(ctx context.Context, refStr string) (*modelArtifact, error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference %q: %w", refStr, err)
	}

	opts := c.options
	opts = append(opts, remote.WithContext(ctx))
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch descriptor: %w", err)
	}

	manifest := &v1.Manifest{}
	if err := json.Unmarshal(desc.Manifest, manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if !isModelArtifact(manifest) {
		return nil, fmt.Errorf("%w (config media type: %s)", errNotModelArtifact, manifest.Config.MediaType)
	}

	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("failed to get image: %w", err)
	}

	configFile, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to get config file: %w", err)
	}

	rawConfig, err := img.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw config: %w", err)
	}

	ggufLayers := extractGGUFLayers(manifest)
	safetensorsLayers := extractSafeTensorsLayers(manifest)
	companionLayers := extractCompanionLayers(manifest)

	return &modelArtifact{
		Reference:         ref,
		Manifest:          manifest,
		Config:            configFile,
		RawManifest:       desc.Manifest,
		RawConfig:         rawConfig,
		ManifestDigest:    desc.Digest.String(),
		Format:            detectModelFormat(len(ggufLayers), len(safetensorsLayers)),
		GGUFLayers:        ggufLayers,
		SafeTensorsLayers: safetensorsLayers,
		CompanionLayers:   companionLayers,
	}, nil
}

// detectModelFormat returns a single format string when either GGUF or
// SafeTensors weight layers are present. When both appear (not expected in
// practice for Docker Model Runner artifacts), GGUF wins because the GGUF
// cataloger is the more established path. Empty result means the manifest has
// no recognized weight layers.
func detectModelFormat(ggufCount, safetensorsCount int) string {
	switch {
	case ggufCount > 0:
		return modelFormatGGUF
	case safetensorsCount > 0:
		return modelFormatSafeTensors
	default:
		return ""
	}
}

// isModelArtifact checks if the manifest represents a model artifact.
func isModelArtifact(manifest *v1.Manifest) bool {
	return strings.HasPrefix(string(manifest.Config.MediaType), modelConfigMediaTypePrefix)
}

// extractGGUFLayers extracts GGUF layer descriptors from the manifest.
func extractGGUFLayers(manifest *v1.Manifest) []v1.Descriptor {
	var ggufLayers []v1.Descriptor
	for _, layer := range manifest.Layers {
		if string(layer.MediaType) == ggufLayerMediaType {
			ggufLayers = append(ggufLayers, layer)
		}
	}
	return ggufLayers
}

// extractSafeTensorsLayers extracts SafeTensors weight-layer descriptors from
// the manifest.
func extractSafeTensorsLayers(manifest *v1.Manifest) []v1.Descriptor {
	var out []v1.Descriptor
	for _, layer := range manifest.Layers {
		if string(layer.MediaType) == safetensorsLayerMediaType {
			out = append(out, layer)
		}
	}
	return out
}

// extractCompanionLayers extracts small, non-weight layers that carry
// cataloger-relevant metadata: README.md / config.json / tokenizer.json /
// generation_config.json under vnd.docker.ai.model.file, and the LICENSE under
// vnd.docker.ai.license.
func extractCompanionLayers(manifest *v1.Manifest) []v1.Descriptor {
	var out []v1.Descriptor
	for _, layer := range manifest.Layers {
		switch string(layer.MediaType) {
		case modelFileMediaType, licenseMediaType:
			out = append(out, layer)
		}
	}
	return out
}

func (c *registryClient) fetchBlobRange(ctx context.Context, ref name.Reference, digest v1.Hash, maxBytes int64) ([]byte, error) {
	repo := ref.Context()

	opts := c.options
	opts = append(opts, remote.WithContext(ctx))
	layer, err := remote.Layer(repo.Digest(digest.String()), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch layer: %w", err)
	}

	reader, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("failed to get layer reader: %w", err)
	}
	// this defer is what causes the download to stop
	//   1. io.ReadFull(reader, data) reads exactly 8MB into the buffer
	//   2. The function returns with data[:n]
	//   3. defer reader.Close() executes, closing the HTTP response body
	//   4. Closing the response body closes the underlying TCP connection
	//   5. The server receives TCP FIN/RST and stops sending
	//   note: some data is already in flight when we close so we will see > 8mb over the wire
	//   the full image will not download given we terminate the reader early here
	defer reader.Close()

	// Note: this is not some arbitrary number picked out of the blue.
	// This is based on the specification of header data found here:
	// https://github.com/ggml-org/ggml/blob/master/docs/gguf.md#file-structure
	data := make([]byte, maxBytes)
	n, err := io.ReadFull(reader, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		// ErrUnexpectedEOF is okay - it means the file is smaller than maxBytes
		return nil, fmt.Errorf("failed to read layer data: %w", err)
	}

	return data[:n], nil
}
