package ocimodelsource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/anchore/stereoscope/pkg/image"
)

const (
	// Model artifact media types as per Docker's OCI artifacts for AI model packaging
	// Reference: https://www.docker.com/blog/oci-artifacts-for-ai-model-packaging/
	ModelConfigMediaType = "application/vnd.docker.ai.model.config.v0.1+json"
	GGUFLayerMediaType   = "application/vnd.docker.ai.gguf.v3"

	// Maximum bytes to fetch via range-GET for GGUF headers
	MaxHeaderBytes = 10 * 1024 * 1024 // 10 MB
)

// RegistryClient handles OCI registry interactions for model artifacts.
type RegistryClient struct {
	options []remote.Option
}

// NewRegistryClient creates a new registry client with authentication from RegistryOptions.
func NewRegistryClient(registryOpts *image.RegistryOptions) (*RegistryClient, error) {
	opts := buildRemoteOptions(registryOpts)

	return &RegistryClient{
		options: opts,
	}, nil
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
		transport := remote.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig.InsecureSkipVerify = true
		opts = append(opts, remote.WithTransport(transport))
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

// ModelArtifact represents a parsed OCI model artifact.
type ModelArtifact struct {
	Reference      name.Reference
	Manifest       *v1.Manifest
	Config         *v1.ConfigFile
	RawManifest    []byte
	RawConfig      []byte
	ManifestDigest string
	GGUFLayers     []v1.Descriptor
}

// FetchModelArtifact fetches and parses an OCI model artifact from the registry.
func (c *RegistryClient) FetchModelArtifact(_ context.Context, refStr string) (*ModelArtifact, error) {
	// Parse reference
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference %q: %w", refStr, err)
	}

	// Fetch descriptor
	desc, err := remote.Get(ref, c.options...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch descriptor: %w", err)
	}

	// Parse manifest
	manifest := &v1.Manifest{}
	if err := json.Unmarshal(desc.Manifest, manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// Check if this is a model artifact
	if !isModelArtifact(manifest) {
		return nil, fmt.Errorf("not a model artifact (config media type: %s)", manifest.Config.MediaType)
	}

	// Fetch config
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

	// Extract GGUF layers
	ggufLayers := extractGGUFLayers(manifest)

	return &ModelArtifact{
		Reference:      ref,
		Manifest:       manifest,
		Config:         configFile,
		RawManifest:    desc.Manifest,
		RawConfig:      rawConfig,
		ManifestDigest: desc.Digest.String(),
		GGUFLayers:     ggufLayers,
	}, nil
}

// isModelArtifact checks if the manifest represents a model artifact.
func isModelArtifact(manifest *v1.Manifest) bool {
	return manifest.Config.MediaType == ModelConfigMediaType
}

// extractGGUFLayers extracts GGUF layer descriptors from the manifest.
func extractGGUFLayers(manifest *v1.Manifest) []v1.Descriptor {
	var ggufLayers []v1.Descriptor
	for _, layer := range manifest.Layers {
		if string(layer.MediaType) == GGUFLayerMediaType {
			ggufLayers = append(ggufLayers, layer)
		}
	}
	return ggufLayers
}

// FetchBlobRange fetches a byte range from a blob in the registry.
// This is used to fetch only the GGUF header without downloading the entire multi-GB file.
func (c *RegistryClient) FetchBlobRange(_ context.Context, ref name.Reference, digest v1.Hash, maxBytes int64) ([]byte, error) {
	// Use the remote package's Layer fetching with our options
	// Then read only the first maxBytes
	repo := ref.Context()

	// Fetch the layer (blob) using remote.Layer
	layer, err := remote.Layer(repo.Digest(digest.String()), c.options...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch layer: %w", err)
	}

	// Get the compressed reader
	reader, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("failed to get layer reader: %w", err)
	}
	defer reader.Close()

	// Read up to maxBytes
	data := make([]byte, maxBytes)
	n, err := io.ReadFull(reader, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		// ErrUnexpectedEOF is okay - it means the file is smaller than maxBytes
		return nil, fmt.Errorf("failed to read layer data: %w", err)
	}

	return data[:n], nil
}

// IsModelArtifactReference checks if a reference points to a model artifact.
// This is a lightweight check that only fetches the manifest.
func (c *RegistryClient) IsModelArtifactReference(_ context.Context, refStr string) (bool, error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse reference %q: %w", refStr, err)
	}

	desc, err := remote.Get(ref, c.options...)
	if err != nil {
		return false, fmt.Errorf("failed to fetch descriptor: %w", err)
	}

	manifest := &v1.Manifest{}
	if err := json.Unmarshal(desc.Manifest, manifest); err != nil {
		return false, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	return isModelArtifact(manifest), nil
}
