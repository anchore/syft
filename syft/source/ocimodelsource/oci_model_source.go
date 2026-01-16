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

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*ociModelSource)(nil)

// Config holds the input configuration for an OCI model artifact source.
type Config struct {
	Reference       string
	RegistryOptions *image.RegistryOptions
	Alias           source.Alias
}

// ociModelSource implements the source.Source interface for OCI model artifacts.
type ociModelSource struct {
	id        artifact.ID
	reference string
	alias     source.Alias
	metadata  source.OCIModelMetadata
	tempDir   string
	resolver  interface {
		file.Resolver
		file.OCIMediaTypeResolver
	}
	mutex *sync.Mutex
}

// NewFromRegistry creates a new OCI model source by fetching the model artifact from a registry.
func NewFromRegistry(ctx context.Context, cfg Config) (source.Source, error) {
	client := newRegistryClient(cfg.RegistryOptions)
	art, err := validateAndFetchArtifact(ctx, client, cfg.Reference)
	if err != nil {
		return nil, err
	}

	metadata := buildMetadata(art)
	tempDir, resolver, err := fetchAndStoreGGUFHeaders(ctx, client, art)
	if err != nil {
		return nil, err
	}

	id := internal.DeriveImageID(cfg.Alias, source.ImageMetadata(metadata))
	return &ociModelSource{
		id:        id,
		reference: cfg.Reference,
		alias:     cfg.Alias,
		metadata:  metadata,
		tempDir:   tempDir,
		resolver:  resolver,
		mutex:     &sync.Mutex{},
	}, nil
}

// validateAndFetchArtifact fetches and validates a model artifact in a single registry call.
func validateAndFetchArtifact(ctx context.Context, client *registryClient, reference string) (*modelArtifact, error) {
	art, err := client.fetchModelArtifact(ctx, reference)
	if err != nil {
		// errNotModelArtifact is wrapped, so callers can use errors.Is() to check
		return nil, err
	}

	if len(art.GGUFLayers) == 0 {
		return nil, fmt.Errorf("model artifact has no GGUF layers")
	}

	return art, nil
}

// fetchAndStoreGGUFHeaders fetches GGUF layer headers and stores them in temp files.
func fetchAndStoreGGUFHeaders(ctx context.Context, client *registryClient, artifact *modelArtifact) (string, *fileresolver.ContainerImageModel, error) {
	tempDir, err := os.MkdirTemp("", "syft-oci-gguf")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	layerFiles := make(map[string]fileresolver.LayerInfo)
	for _, layer := range artifact.GGUFLayers {
		li, err := fetchSingleGGUFHeader(ctx, client, artifact.Reference, layer, tempDir)
		if err != nil {
			osErr := os.RemoveAll(tempDir)
			if osErr != nil {
				log.Errorf("unable to remove temp directory (%s): %v", tempDir, err)
			}
			return "", nil, err
		}
		layerFiles[layer.Digest.String()] = li
	}

	resolver := fileresolver.NewContainerImageModel(tempDir, layerFiles)

	return tempDir, resolver, nil
}

// fetchSingleGGUFHeader fetches a single GGUF layer header and writes it to a temp file.
func fetchSingleGGUFHeader(ctx context.Context, client *registryClient, ref name.Reference, layer v1.Descriptor, tempDir string) (fileresolver.LayerInfo, error) {
	headerData, err := client.fetchBlobRange(ctx, ref, layer.Digest, maxHeaderBytes)
	if err != nil {
		return fileresolver.LayerInfo{}, fmt.Errorf("failed to fetch GGUF layer header: %w", err)
	}

	digestStr := layer.Digest.String()
	safeDigest := strings.ReplaceAll(digestStr, ":", "-")
	tempPath := filepath.Join(tempDir, safeDigest+".gguf")
	if err := os.WriteFile(tempPath, headerData, 0600); err != nil {
		return fileresolver.LayerInfo{}, fmt.Errorf("failed to write temp file: %w", err)
	}

	return fileresolver.LayerInfo{
		TempPath:  tempPath,
		MediaType: string(layer.MediaType),
	}, nil
}

// buildMetadata constructs OCIModelMetadata from a modelArtifact.
func buildMetadata(artifact *modelArtifact) source.OCIModelMetadata {
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
	return source.OCIModelMetadata{
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
	return s.resolver, nil
}

// Close cleans up temporary files. Safe to call multiple times.
func (s *ociModelSource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.tempDir == "" {
		return nil
	}

	err := os.RemoveAll(s.tempDir)
	s.tempDir = ""
	s.resolver = nil
	return err
}
