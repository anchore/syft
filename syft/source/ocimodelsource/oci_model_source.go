package ocimodelsource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*ociModelSource)(nil)

// layerInfo holds information about a layer file stored on disk.
type layerInfo struct {
	TempPath  string // Path to the temp file on disk
	MediaType string // OCI media type of the layer
}

// Config holds the input configuration for an OCI model artifact source.
type Config struct {
	Reference    string
	RegistryOpts *image.RegistryOptions
	Alias        source.Alias
}

// ociModelSource implements the source.Source interface for OCI model artifacts.
type ociModelSource struct {
	id         artifact.ID
	reference  string
	alias      source.Alias
	metadata   *OCIModelMetadata
	tempDir    string
	layerFiles map[string]layerInfo
	resolver   interface {
		file.Resolver
		file.OciLayerResolver
	}
	mutex *sync.Mutex
}

// NewFromRegistry creates a new OCI model source by fetching the model artifact from a registry.
func NewFromRegistry(ctx context.Context, cfg Config) (source.Source, error) {
	client := newRegistryClient(cfg.RegistryOpts)
	artifact, err := validateAndFetchArtifact(ctx, client, cfg.Reference)
	if err != nil {
		return nil, err
	}

	metadata := buildMetadata(artifact)
	tempDir, layerFiles, err := fetchAndStoreGGUFHeaders(ctx, client, artifact)
	if err != nil {
		return nil, err
	}

	id := deriveID(cfg.Reference, cfg.Alias, metadata.ManifestDigest)
	return &ociModelSource{
		id:         id,
		reference:  cfg.Reference,
		alias:      cfg.Alias,
		metadata:   metadata,
		tempDir:    tempDir,
		layerFiles: layerFiles,
		mutex:      &sync.Mutex{},
	}, nil
}

// validateAndFetchArtifact fetches and validates a model artifact in a single registry call.
func validateAndFetchArtifact(ctx context.Context, client *registryClient, reference string) (*modelArtifact, error) {
	artifact, err := client.fetchModelArtifact(ctx, reference)
	if err != nil {
		// errNotModelArtifact is wrapped, so callers can use errors.Is() to check
		return nil, err
	}

	if len(artifact.GGUFLayers) == 0 {
		return nil, fmt.Errorf("model artifact has no GGUF layers")
	}

	return artifact, nil
}

// fetchAndStoreGGUFHeaders fetches GGUF layer headers and stores them in temp files.
func fetchAndStoreGGUFHeaders(ctx context.Context, client *registryClient, artifact *modelArtifact) (string, map[string]layerInfo, error) {
	tempDir, err := os.MkdirTemp("", "oci-gguf")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	layerFiles := make(map[string]layerInfo)
	for _, layer := range artifact.GGUFLayers {
		li, err := fetchSingleGGUFHeader(ctx, client, artifact.Reference, layer, tempDir)
		if err != nil {
			os.RemoveAll(tempDir)
			return "", nil, err
		}
		layerFiles[layer.Digest.String()] = li
	}

	return tempDir, layerFiles, nil
}

// fetchSingleGGUFHeader fetches a single GGUF layer header and writes it to a temp file.
func fetchSingleGGUFHeader(ctx context.Context, client *registryClient, ref name.Reference, layer v1.Descriptor, tempDir string) (layerInfo, error) {
	headerData, err := client.fetchBlobRange(ctx, ref, layer.Digest, maxHeaderBytes)
	if err != nil {
		return layerInfo{}, fmt.Errorf("failed to fetch GGUF layer header: %w", err)
	}

	digestStr := layer.Digest.String()
	safeDigest := strings.ReplaceAll(digestStr, ":", "-")
	tempPath := filepath.Join(tempDir, safeDigest+".gguf")
	if err := os.WriteFile(tempPath, headerData, 0600); err != nil {
		return layerInfo{}, fmt.Errorf("failed to write temp file: %w", err)
	}

	return layerInfo{
		TempPath:  tempPath,
		MediaType: string(layer.MediaType),
	}, nil
}

// buildMetadata constructs OCIModelMetadata from a modelArtifact.
func buildMetadata(artifact *modelArtifact) *OCIModelMetadata {
	// layers
	layers := make([]source.LayerMetadata, len(artifact.Manifest.Layers))
	for i, layer := range artifact.Manifest.Layers {
		layers[i] = source.LayerMetadata{
			MediaType: string(layer.MediaType),
			Digest:    layer.Digest.String(),
			Size:      layer.Size,
		}
	}

	// tags
	var tags []string
	if tagged, ok := artifact.Reference.(interface{ TagStr() string }); ok {
		if tag := tagged.TagStr(); tag != "" {
			tags = []string{tag}
		}
	}

	// digests
	var repoDigests []string
	if artifact.ManifestDigest != "" {
		repoDigests = []string{artifact.Reference.Context().String() + "@" + artifact.ManifestDigest}
	}

	// metadata
	return &OCIModelMetadata{
		ImageMetadata: source.ImageMetadata{
			UserInput:      artifact.Reference.String(),
			ID:             artifact.ManifestDigest,
			ManifestDigest: artifact.ManifestDigest,
			MediaType:      string(artifact.Manifest.MediaType),
			Tags:           tags,
			Size:           calculateTotalSize(layers),
			Layers:         layers,
			RawManifest:    artifact.RawManifest,
			RawConfig:      artifact.RawConfig,
			RepoDigests:    repoDigests,
			Architecture:   artifact.Config.Architecture,
			Variant:        artifact.Config.Variant,
			OS:             artifact.Config.OS,
			Labels:         artifact.Config.Config.Labels,
		},
		Annotations: extractManifestAnnotations(artifact.Manifest),
	}
}

// extractManifestAnnotations extracts annotations from the manifest.
func extractManifestAnnotations(manifest *v1.Manifest) map[string]string {
	if manifest == nil || manifest.Annotations == nil {
		return make(map[string]string)
	}
	return manifest.Annotations
}

// calculateTotalSize sums up the size of all layers.
func calculateTotalSize(layers []source.LayerMetadata) int64 {
	var total int64
	for _, layer := range layers {
		total += layer.Size
	}
	return total
}

// deriveID generates an artifact ID from the reference, alias, and manifest digest.
func deriveID(reference string, alias source.Alias, manifestDigest string) artifact.ID {
	var info string

	switch {
	case !alias.IsEmpty():
		// Use alias for stable artifact ID
		info = fmt.Sprintf("%s@%s", alias.Name, alias.Version)
	case manifestDigest != "":
		// Use manifest digest
		info = manifestDigest
	default:
		// Fall back to reference
		info = reference
	}

	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(info).String())
}

// ID returns the artifact ID.
func (s *ociModelSource) ID() artifact.ID {
	return s.id
}

// Describe returns a description of the source.
func (s *ociModelSource) Describe() source.Description {
	name := s.reference
	version := ""
	supplier := ""

	if !s.alias.IsEmpty() {
		if s.alias.Name != "" {
			name = s.alias.Name
		}
		if s.alias.Version != "" {
			version = s.alias.Version
		}
		if s.alias.Supplier != "" {
			supplier = s.alias.Supplier
		}
	}

	return source.Description{
		ID:       string(s.id),
		Name:     name,
		Version:  version,
		Supplier: supplier,
		Metadata: s.metadata,
	}
}

// FileResolver returns a file resolver for accessing header of GGUF files.
func (s *ociModelSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver == nil {
		s.resolver = newOCIModelResolver(s.tempDir, s.layerFiles)
	}

	return s.resolver, nil
}

// Close cleans up temporary files.
func (s *ociModelSource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		if r, ok := s.resolver.(*ociModelResolver); ok {
			if err := r.cleanup(); err != nil {
				return err
			}
		}
		s.resolver = nil
	}

	return nil
}
