package ocimodelsource

import (
	"context"
	"fmt"
	"sync"

	"github.com/opencontainers/go-digest"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*ociModelSource)(nil)

// Config holds the configuration for an OCI model artifact source.
type Config struct {
	Reference   string
	Platform    string
	Alias       source.Alias
	Client      *RegistryClient
	Metadata    *OCIModelMetadata
	TempFiles   map[string]string // Virtual path -> temp file path
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

	// Fetch GGUF layer headers via range-GET
	tempFiles := make(map[string]string)
	ggufLayers := make([]GGUFLayerInfo, 0, len(artifact.GGUFLayers))

	for idx, layer := range artifact.GGUFLayers {
		log.WithFields("digest", layer.Digest, "size", layer.Size).Debug("fetching GGUF layer header")

		// Fetch header via range-GET
		headerData, err := client.FetchBlobRange(context.Background(), artifact.Reference, layer.Digest, MaxHeaderBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch GGUF layer header: %w", err)
		}

		// Extract virtual path from annotations
		virtualPath := extractVirtualPath(idx, extractAnnotations(layer.Annotations))

		// Create temp file
		tempPath, err := createTempFileFromData(headerData, virtualPath)
		if err != nil {
			// Clean up any previously created temp files
			for _, path := range tempFiles {
				_ = removeFile(path)
			}
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}

		tempFiles[virtualPath] = tempPath

		// Add to GGUF layers metadata
		ggufLayers = append(ggufLayers, GGUFLayerInfo{
			Digest:       layer.Digest.String(),
			Size:         layer.Size,
			MediaType:    string(layer.MediaType),
			Annotations:  extractAnnotations(layer.Annotations),
			FetchedBytes: int64(len(headerData)),
		})

		log.WithFields("virtualPath", virtualPath, "tempPath", tempPath, "bytes", len(headerData)).Debug("created temp file for GGUF header")
	}

	// Update metadata with GGUF layers
	metadata.GGUFLayers = ggufLayers
	metadata.ModelFormat = "gguf"

	// Build config
	config := Config{
		Reference: artifact.Reference.String(),
		Alias:     alias,
		Client:    client,
		Metadata:  metadata,
		TempFiles: tempFiles,
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
		Annotations:    extractManifestAnnotations(artifact.Manifest),
	}
}

// extractAnnotations converts v1 annotations to a string map.
func extractAnnotations(annotations map[string]string) map[string]string {
	if annotations == nil {
		return make(map[string]string)
	}
	return annotations
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

	if !cfg.Alias.IsEmpty() {
		// Use alias for stable artifact ID
		info = fmt.Sprintf("%s@%s", cfg.Alias.Name, cfg.Alias.Version)
	} else if cfg.Metadata.ManifestDigest != "" {
		// Use manifest digest
		info = cfg.Metadata.ManifestDigest
	} else {
		// Fall back to reference
		log.Warn("no explicit name/version or manifest digest, deriving artifact ID from reference")
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
func (s *ociModelSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver == nil {
		s.resolver = newOCIModelResolver(s.config.TempFiles)
	}

	return s.resolver, nil
}

// Close cleans up temporary files.
func (s *ociModelSource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		if err := s.resolver.cleanup(); err != nil {
			log.WithFields("error", err).Warn("failed to cleanup temp files")
			return err
		}
		s.resolver = nil
	}

	return nil
}

// removeFile removes a file and logs any errors.
func removeFile(path string) error {
	return nil // Placeholder for now
}
