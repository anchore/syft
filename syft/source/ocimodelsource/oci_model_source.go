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
	tempDir, resolver, err := fetchAndStoreModelHeaders(ctx, client, art)
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

	if art.Format == "" {
		return nil, fmt.Errorf("model artifact has no GGUF or SafeTensors weight layers")
	}

	return art, nil
}

// fetchAndStoreModelHeaders fetches the blobs needed to catalog a Docker AI
// model artifact and stores them on disk so the ContainerImageModel resolver
// can serve them by media type:
//
//   - For GGUF: the first maxHeaderBytes of each weight layer (existing behavior).
//   - For SafeTensors: the model-config blob (already in memory as RawConfig)
//     plus each companion layer in full. We deliberately skip the multi-GB
//     safetensors weight layers — the config blob carries aggregate metadata
//     (format, quantization, parameter count, tensor count, total size) that
//     the cataloger needs, and individual shard headers are not yet used.
func fetchAndStoreModelHeaders(ctx context.Context, client *registryClient, artifact *modelArtifact) (string, *fileresolver.ContainerImageModel, error) {
	tempDir, err := os.MkdirTemp("", "syft-oci-model")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	cleanup := func() {
		if osErr := os.RemoveAll(tempDir); osErr != nil {
			log.Errorf("unable to remove temp directory (%s): %v", tempDir, osErr)
		}
	}

	layerFiles := make(map[string]fileresolver.LayerInfo)

	// GGUF weight-layer headers (unchanged).
	for _, layer := range artifact.GGUFLayers {
		li, err := fetchSingleGGUFHeader(ctx, client, artifact.Reference, layer, tempDir)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		layerFiles[layer.Digest.String()] = li
	}

	// For SafeTensors artifacts, expose the model-config blob to the resolver
	// so parseSafeTensorsOCIConfig can match it by media type. RawConfig was
	// already fetched as part of the manifest walk.
	if artifact.Format == modelFormatSafeTensors && len(artifact.RawConfig) > 0 {
		li, err := storeConfigBlobAsLayer(artifact, tempDir)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		layerFiles[artifact.Manifest.Config.Digest.String()] = li
	}

	// Companion layers (README, config.json, tokenizer.json, LICENSE). Small by
	// convention; fetched in full up to maxCompanionBytes.
	if artifact.Format == modelFormatSafeTensors {
		for _, layer := range artifact.CompanionLayers {
			li, err := fetchCompanionLayer(ctx, client, artifact.Reference, layer, tempDir)
			if err != nil {
				cleanup()
				return "", nil, err
			}
			layerFiles[layer.Digest.String()] = li
		}
	}

	resolver := fileresolver.NewContainerImageModel(tempDir, layerFiles)

	return tempDir, resolver, nil
}

// storeConfigBlobAsLayer writes the already-fetched raw config bytes to a temp
// file so the resolver can serve them via media type.
func storeConfigBlobAsLayer(artifact *modelArtifact, tempDir string) (fileresolver.LayerInfo, error) {
	digest := artifact.Manifest.Config.Digest.String()
	safeDigest := strings.ReplaceAll(digest, ":", "-")
	tempPath := filepath.Join(tempDir, safeDigest+".config.json")
	if err := os.WriteFile(tempPath, artifact.RawConfig, 0600); err != nil {
		return fileresolver.LayerInfo{}, fmt.Errorf("failed to write config blob: %w", err)
	}
	return fileresolver.LayerInfo{
		TempPath:  tempPath,
		MediaType: string(artifact.Manifest.Config.MediaType),
	}, nil
}

// fetchCompanionLayer downloads a companion (non-weight) layer to a temp file.
// Unlike weight layers we fetch up to maxCompanionBytes, which comfortably
// covers READMEs, HF config.json, tokenizer.json, and LICENSE text.
func fetchCompanionLayer(ctx context.Context, client *registryClient, ref name.Reference, layer v1.Descriptor, tempDir string) (fileresolver.LayerInfo, error) {
	data, err := client.fetchBlobRange(ctx, ref, layer.Digest, maxCompanionBytes)
	if err != nil {
		return fileresolver.LayerInfo{}, fmt.Errorf("failed to fetch companion layer: %w", err)
	}
	safeDigest := strings.ReplaceAll(layer.Digest.String(), ":", "-")
	tempPath := filepath.Join(tempDir, safeDigest+".blob")
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fileresolver.LayerInfo{}, fmt.Errorf("failed to write companion temp file: %w", err)
	}
	return fileresolver.LayerInfo{
		TempPath:  tempPath,
		MediaType: string(layer.MediaType),
	}, nil
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
