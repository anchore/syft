package ocimodelsource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*ociModelSource)(nil)

// LayerInfo holds information about a layer file stored on disk.
type LayerInfo struct {
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
	layerFiles map[string]LayerInfo
	resolver   *ociModelResolver
	mutex      *sync.Mutex
}

// NewFromRegistry creates a new OCI model source by fetching the model artifact from a registry.
// This handles all setup: registry client creation, artifact validation, metadata fetching,
// and temp file creation for GGUF layer headers.
func NewFromRegistry(ctx context.Context, cfg Config) (source.Source, error) {
	// Create registry client
	client, err := NewRegistryClient(cfg.RegistryOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %w", err)
	}

	// Check if this is a model artifact (lightweight check)
	log.WithFields("reference", cfg.Reference).Debug("checking if reference is a model artifact")

	isModel, err := client.IsModelArtifactReference(ctx, cfg.Reference)
	if err != nil {
		log.WithFields("reference", cfg.Reference, "error", err).Debug("failed to check if reference is a model artifact")
		return nil, fmt.Errorf("not an OCI model artifact: %w", err)
	}

	if !isModel {
		log.WithFields("reference", cfg.Reference).Debug("reference is not a model artifact")
		return nil, fmt.Errorf("not an OCI model artifact")
	}

	log.WithFields("reference", cfg.Reference).Info("detected OCI model artifact, fetching headers")

	// Fetch the full model artifact with metadata
	artifact, err := client.FetchModelArtifact(ctx, cfg.Reference)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch model artifact: %w", err)
	}

	// Check if there are any GGUF layers
	if len(artifact.GGUFLayers) == 0 {
		log.WithFields("reference", cfg.Reference).Warn("model artifact has no GGUF layers")
		return nil, fmt.Errorf("model artifact has no GGUF layers")
	}

	log.WithFields("reference", cfg.Reference, "ggufLayers", len(artifact.GGUFLayers)).Info("found GGUF layers in model artifact")

	// Build metadata
	metadata := buildMetadata(artifact)

	// Create temp directory for GGUF layer files
	tempDir, err := os.MkdirTemp("", "oci-gguf-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Fetch GGUF layer headers via range-GET
	layerFiles := make(map[string]LayerInfo)

	for _, layer := range artifact.GGUFLayers {
		log.WithFields("digest", layer.Digest, "size", layer.Size).Debug("fetching GGUF layer header")

		// Fetch header via range-GET
		headerData, err := client.FetchBlobRange(ctx, artifact.Reference, layer.Digest, MaxHeaderBytes)
		if err != nil {
			os.RemoveAll(tempDir)
			return nil, fmt.Errorf("failed to fetch GGUF layer header: %w", err)
		}

		// Create temp file as <tempDir>/<digest>.gguf
		// Use the algorithm:hash format, replacing : with - for filesystem compatibility
		digestStr := layer.Digest.String()
		safeDigest := strings.ReplaceAll(digestStr, ":", "-")
		tempPath := filepath.Join(tempDir, safeDigest+".gguf")

		if err := os.WriteFile(tempPath, headerData, 0600); err != nil {
			os.RemoveAll(tempDir)
			return nil, fmt.Errorf("failed to write temp file: %w", err)
		}

		layerFiles[digestStr] = LayerInfo{
			TempPath:  tempPath,
			MediaType: string(layer.MediaType),
		}
	}

	// Derive artifact ID
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

// buildMetadata constructs OCIModelMetadata from a ModelArtifact.
func buildMetadata(artifact *ModelArtifact) *OCIModelMetadata {
	// Extract layers
	layers := make([]source.LayerMetadata, len(artifact.Manifest.Layers))
	for i, layer := range artifact.Manifest.Layers {
		layers[i] = source.LayerMetadata{
			MediaType: string(layer.MediaType),
			Digest:    layer.Digest.String(),
			Size:      layer.Size,
		}
	}

	// Extract tags
	var tags []string
	if tagged, ok := artifact.Reference.(interface{ TagStr() string }); ok {
		if tag := tagged.TagStr(); tag != "" {
			tags = []string{tag}
		}
	}

	// Extract repo digests
	var repoDigests []string
	if artifact.ManifestDigest != "" {
		repoDigests = []string{artifact.Reference.Context().String() + "@" + artifact.ManifestDigest}
	}

	// Build metadata
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
func extractManifestAnnotations(manifest interface{}) map[string]string {
	// v1.Manifest has Annotations field
	if m, ok := manifest.(interface{ GetAnnotations() map[string]string }); ok {
		return m.GetAnnotations()
	}
	return make(map[string]string)
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

// FileResolver returns a file resolver for accessing GGUF header files.
// The returned resolver also implements OCIResolver for layer-aware access.
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
		if err := s.resolver.cleanup(); err != nil {
			return err
		}
		s.resolver = nil
	}

	return nil
}
