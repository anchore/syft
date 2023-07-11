package source

import (
	"context"
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/opencontainers/go-digest"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
)

var _ Source = (*StereoscopeImageSource)(nil)

type StereoscopeImageConfig struct {
	Reference       string
	From            image.Source
	Platform        *image.Platform
	RegistryOptions *image.RegistryOptions
	Exclude         ExcludeConfig
	Alias           Alias
}

type StereoscopeImageSource struct {
	id       artifact.ID
	config   StereoscopeImageConfig
	image    *image.Image
	metadata StereoscopeImageSourceMetadata
}

func NewFromStereoscopeImageObject(img *image.Image, reference string, alias *Alias) (*StereoscopeImageSource, error) {
	var aliasVal Alias
	if !alias.IsEmpty() {
		aliasVal = *alias
	}
	cfg := StereoscopeImageConfig{
		Reference: reference,
		Alias:     aliasVal,
	}
	metadata := imageMetadataFromStereoscopeImage(img, cfg.Reference)

	return &StereoscopeImageSource{
		id:       deriveIDFromStereoscopeImage(cfg.Alias, metadata),
		config:   cfg,
		image:    img,
		metadata: metadata,
	}, nil
}

func NewFromStereoscopeImage(cfg StereoscopeImageConfig) (*StereoscopeImageSource, error) {
	ctx := context.TODO()

	var opts []stereoscope.Option
	if cfg.RegistryOptions != nil {
		opts = append(opts, stereoscope.WithRegistryOptions(*cfg.RegistryOptions))
	}

	if cfg.Platform != nil {
		opts = append(opts, stereoscope.WithPlatform(cfg.Platform.String()))
	}

	img, err := stereoscope.GetImageFromSource(ctx, cfg.Reference, cfg.From, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to load image: %w", err)
	}

	metadata := imageMetadataFromStereoscopeImage(img, cfg.Reference)

	return &StereoscopeImageSource{
		id:       deriveIDFromStereoscopeImage(cfg.Alias, metadata),
		config:   cfg,
		image:    img,
		metadata: metadata,
	}, nil
}

func (s StereoscopeImageSource) ID() artifact.ID {
	return s.id
}

func (s StereoscopeImageSource) Describe() Description {
	name := s.metadata.UserInput
	version := s.metadata.ManifestDigest

	a := s.config.Alias
	if a.Name != "" {
		name = a.Name
	}

	if a.Version != "" {
		version = a.Version
	}

	return Description{
		ID:       string(s.id),
		Name:     name,
		Version:  version,
		Metadata: s.metadata,
	}
}

func (s StereoscopeImageSource) FileResolver(scope Scope) (file.Resolver, error) {
	var res file.Resolver
	var err error

	switch scope {
	case SquashedScope:
		res, err = fileresolver.NewFromContainerImageSquash(s.image)
	case AllLayersScope:
		res, err = fileresolver.NewFromContainerImageAllLayers(s.image)
	default:
		return nil, fmt.Errorf("bad image scope provided: %+v", scope)
	}

	if err != nil {
		return nil, err
	}

	// image tree contains all paths, so we filter out the excluded entries afterward
	if len(s.config.Exclude.Paths) > 0 {
		res = fileresolver.NewExcludingDecorator(res, getImageExclusionFunction(s.config.Exclude.Paths))
	}

	return res, nil
}

func (s StereoscopeImageSource) Close() error {
	if s.image == nil {
		return nil
	}
	return s.image.Cleanup()
}

func imageMetadataFromStereoscopeImage(img *image.Image, reference string) StereoscopeImageSourceMetadata {
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}

	layers := make([]StereoscopeLayerMetadata, len(img.Layers))
	for idx, l := range img.Layers {
		layers[idx] = StereoscopeLayerMetadata{
			MediaType: string(l.Metadata.MediaType),
			Digest:    l.Metadata.Digest,
			Size:      l.Metadata.Size,
		}
	}

	return StereoscopeImageSourceMetadata{
		ID:             img.Metadata.ID,
		UserInput:      reference,
		ManifestDigest: img.Metadata.ManifestDigest,
		Size:           img.Metadata.Size,
		MediaType:      string(img.Metadata.MediaType),
		Tags:           tags,
		Layers:         layers,
		RawConfig:      img.Metadata.RawConfig,
		RawManifest:    img.Metadata.RawManifest,
		RepoDigests:    img.Metadata.RepoDigests,
		Architecture:   img.Metadata.Architecture,
		Variant:        img.Metadata.Variant,
		OS:             img.Metadata.OS,
	}
}

// deriveIDFromStereoscopeImage derives an artifact ID from the given image metadata. The order of data precedence is:
//  1. prefer a digest of the raw container image manifest
//  2. if no manifest digest is available, calculate a chain ID from the image layer metadata
//  3. if no layer metadata is available, use the user input string
//
// in all cases, if an alias is provided, it is additionally considered in the ID calculation. This allows for the
// same image to be scanned multiple times with different aliases and be considered logically different.
func deriveIDFromStereoscopeImage(alias Alias, metadata StereoscopeImageSourceMetadata) artifact.ID {
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

	return artifactIDFromDigest(input)
}

func calculateChainID(lm []StereoscopeLayerMetadata) string {
	if len(lm) < 1 {
		return ""
	}

	// DiffID(L0) = digest of layer 0
	// https://github.com/anchore/stereoscope/blob/1b1b744a919964f38d14e1416fb3f25221b761ce/pkg/image/layer_metadata.go#L19-L32
	chainID := lm[0].Digest
	id := chain(chainID, lm[1:])

	return id
}

func chain(chainID string, layers []StereoscopeLayerMetadata) string {
	if len(layers) < 1 {
		return chainID
	}

	chainID = digest.Canonical.FromString(layers[0].Digest + " " + chainID).String()
	return chain(chainID, layers[1:])
}

func getImageExclusionFunction(exclusions []string) func(string) bool {
	if len(exclusions) == 0 {
		return nil
	}
	// add subpath exclusions
	for _, exclusion := range exclusions {
		exclusions = append(exclusions, exclusion+"/**")
	}
	return func(path string) bool {
		for _, exclusion := range exclusions {
			matches, err := doublestar.Match(exclusion, path)
			if err != nil {
				return false
			}
			if matches {
				return true
			}
		}
		return false
	}
}
