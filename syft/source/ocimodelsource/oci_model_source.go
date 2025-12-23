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

// Config holds the configuration for an OCI model artifact source.
type Config struct {
	Reference string
	Platform  string
	Alias     source.Alias
	Client    *RegistryClient
	Metadata  *OCIModelMetadata

	// Temp directory containing all layer files
	TempDir string

	// Layer files indexed by digest
	LayerFiles map[string]LayerInfo // digest -> layer info

	// OCI layer-aware fields for the resolver
	Ref      name.Reference // parsed OCI reference
	Manifest *v1.Manifest   // manifest containing layer information
}

// ociModelSource implements the source.Source interface for OCI model artifacts.
type ociModelSource struct {
	id       artifact.ID
	config   Config
	resolver *ociModelResolver
	mutex    *sync.Mutex
}

// NewFromArtifact creates a new OCI model source from a fetched model artifact.
func NewFromArtifact(artifact *ModelArtifact, client *RegistryClient, alias source.Alias) (source.Source, error) {
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
		headerData, err := client.FetchBlobRange(context.Background(), artifact.Reference, layer.Digest, MaxHeaderBytes)
		if err != nil {
			// Clean up temp dir on error
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

	// Build config
	config := Config{
		Reference:  artifact.Reference.String(),
		Alias:      alias,
		Client:     client,
		Metadata:   metadata,
		TempDir:    tempDir,
		LayerFiles: layerFiles,
		Ref:        artifact.Reference,
		Manifest:   artifact.Manifest,
	}

	// Derive artifact ID
	id := deriveIDFromArtifact(config)

	return &ociModelSource{
		id:     id,
		config: config,
		mutex:  &sync.Mutex{},
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

// deriveIDFromArtifact generates an artifact ID from the config.
func deriveIDFromArtifact(cfg Config) artifact.ID {
	var info string

	switch {
	case !cfg.Alias.IsEmpty():
		// Use alias for stable artifact ID
		info = fmt.Sprintf("%s@%s", cfg.Alias.Name, cfg.Alias.Version)
	case cfg.Metadata.ManifestDigest != "":
		// Use manifest digest
		info = cfg.Metadata.ManifestDigest
	default:
		// Fall back to reference
		info = cfg.Reference
	}

	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(info).String())
}

// ID returns the artifact ID.
func (s *ociModelSource) ID() artifact.ID {
	return s.id
}

// Describe returns a description of the source.
func (s *ociModelSource) Describe() source.Description {
	name := s.config.Reference
	version := ""
	supplier := ""

	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}
		if a.Version != "" {
			version = a.Version
		}
		if a.Supplier != "" {
			supplier = a.Supplier
		}
	}

	return source.Description{
		ID:       string(s.id),
		Name:     name,
		Version:  version,
		Supplier: supplier,
		Metadata: s.config.Metadata,
	}
}

// FileResolver returns a file resolver for accessing GGUF header files.
// The returned resolver also implements OCIResolver for layer-aware access.
func (s *ociModelSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver == nil {
		s.resolver = newOCIModelResolver(s.config.TempDir, s.config.LayerFiles)
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
