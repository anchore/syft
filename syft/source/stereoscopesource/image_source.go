package stereoscopesource

import (
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*stereoscopeImageSource)(nil)

type ImageConfig struct {
	Reference       string
	Platform        *image.Platform
	RegistryOptions *image.RegistryOptions
	Exclude         source.ExcludeConfig
	Alias           source.Alias
}

type stereoscopeImageSource struct {
	id       artifact.ID
	config   ImageConfig
	image    *image.Image
	metadata source.ImageMetadata
}

func New(img *image.Image, cfg ImageConfig) source.Source {
	metadata := imageMetadataFromStereoscopeImage(img, cfg.Reference)
	return &stereoscopeImageSource{
		id:       deriveIDFromStereoscopeImage(cfg.Alias, metadata),
		config:   cfg,
		image:    img,
		metadata: metadata,
	}
}

func (s stereoscopeImageSource) ID() artifact.ID {
	return s.id
}

func (s stereoscopeImageSource) Describe() source.Description {
	a := s.config.Alias

	name := a.Name
	supplier := a.Supplier
	nameIfUnset := func(n string) {
		if name != "" {
			return
		}
		name = n
	}

	version := a.Version
	versionIfUnset := func(v string) {
		if version != "" && version != "latest" {
			return
		}
		version = v
	}

	ref, err := reference.Parse(s.metadata.UserInput)
	if err != nil {
		log.Debugf("unable to parse image ref: %s", s.config.Reference)
	} else {
		if ref, ok := ref.(reference.Named); ok {
			nameIfUnset(ref.Name())
		}

		if ref, ok := ref.(reference.NamedTagged); ok {
			versionIfUnset(ref.Tag())
		}

		if ref, ok := ref.(reference.Digested); ok {
			versionIfUnset(ref.Digest().String())
		}
	}

	nameIfUnset(s.metadata.UserInput)
	versionIfUnset(s.metadata.ManifestDigest)

	return source.Description{
		ID:       string(s.id),
		Name:     name,
		Version:  version,
		Supplier: supplier,
		Metadata: s.metadata,
	}
}

func (s stereoscopeImageSource) FileResolver(scope source.Scope) (file.Resolver, error) {
	var res file.Resolver
	var err error

	switch scope {
	case source.SquashedScope:
		res, err = fileresolver.NewFromContainerImageSquash(s.image)
	case source.AllLayersScope:
		res, err = fileresolver.NewFromContainerImageAllLayers(s.image)
	case source.DeepSquashedScope:
		res, err = fileresolver.NewFromContainerImageDeepSquash(s.image)
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

func (s stereoscopeImageSource) Close() error {
	if s.image == nil {
		return nil
	}
	return s.image.Cleanup()
}

func imageMetadataFromStereoscopeImage(img *image.Image, reference string) source.ImageMetadata {
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}

	layers := make([]source.LayerMetadata, len(img.Layers))
	for idx, l := range img.Layers {
		layers[idx] = source.LayerMetadata{
			MediaType: string(l.Metadata.MediaType),
			Digest:    l.Metadata.Digest,
			Size:      l.Metadata.Size,
		}
	}

	return source.ImageMetadata{
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
		Labels:         img.Metadata.Config.Config.Labels,
	}
}

// deriveIDFromStereoscopeImage derives an artifact ID from the given image metadata. The order of data precedence is:
//  1. prefer a digest of the raw container image manifest
//  2. if no manifest digest is available, calculate a chain ID from the image layer metadata
//  3. if no layer metadata is available, use the user input string
//
// in all cases, if an alias is provided, it is additionally considered in the ID calculation. This allows for the
// same image to be scanned multiple times with different aliases and be considered logically different.
func deriveIDFromStereoscopeImage(alias source.Alias, metadata source.ImageMetadata) artifact.ID {
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

	return internal.ArtifactIDFromDigest(input)
}

func calculateChainID(lm []source.LayerMetadata) string {
	if len(lm) < 1 {
		return ""
	}

	// DiffID(L0) = digest of layer 0
	// https://github.com/anchore/stereoscope/blob/1b1b744a919964f38d14e1416fb3f25221b761ce/pkg/image/layer_metadata.go#L19-L32
	chainID := lm[0].Digest
	id := chain(chainID, lm[1:])

	return id
}

func chain(chainID string, layers []source.LayerMetadata) string {
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
