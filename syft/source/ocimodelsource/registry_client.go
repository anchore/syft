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

	// Maximum bytes to read/return for GGUF headers
	maxHeaderBytes = 8 * 1024 * 1024 // 8 MB
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
	GGUFLayers     []v1.Descriptor
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

	return &modelArtifact{
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
