package fileresolver

import (
	"context"
	"io"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ContainerImageSquashAllLayers)(nil)

// ContainerImageSquashAllLayers implements path and content access for the Squashed all layers source option for container image data sources.
type ContainerImageSquashAllLayers struct {
	squashed  *ContainerImageSquash
	allLayers *ContainerImageAllLayers
}

// NewFromContainerImageSquashAllLayers returns a new resolver from the perspective of all image layers for the given image.
func NewFromContainerImageSquashAllLayers(img *image.Image) (*ContainerImageSquashAllLayers, error) {
	squashed, err := NewFromContainerImageSquash(img)
	if err != nil {
		return nil, err
	}

	allLayers, err := NewFromContainerImageAllLayers(img)
	if err != nil {
		return nil, err
	}

	return &ContainerImageSquashAllLayers{
		squashed:  squashed,
		allLayers: allLayers,
	}, nil
}

// HasPath indicates if the given path exists in the underlying source.
func (i *ContainerImageSquashAllLayers) HasPath(path string) bool {
	return i.squashed.HasPath(path)
}

// FilesByPath returns all file.References that match the given paths from any layer in the image.
func (i *ContainerImageSquashAllLayers) FilesByPath(paths ...string) ([]file.Location, error) {
	squashedLocations, err := i.squashed.FilesByPath(paths...)
	if err != nil {
		return nil, err
	}

	allLayersLocations, err := i.allLayers.FilesByPath(paths...)
	if err != nil {
		return nil, err
	}

	var mergedLocations []file.Location
	for _, l := range squashedLocations {
		mergedLocations = append(mergedLocations, file.Location{
			LocationData: l.LocationData,
			LocationMetadata: file.LocationMetadata{
				Annotations:     l.Annotations,
				IsSquashedLayer: true,
			},
		})
	}

	for _, l := range allLayersLocations {
		mergedLocations = append(mergedLocations, file.Location{
			LocationData: l.LocationData,
			LocationMetadata: file.LocationMetadata{
				Annotations:     l.Annotations,
				IsSquashedLayer: false,
			},
		})
	}

	return mergedLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (i *ContainerImageSquashAllLayers) FilesByGlob(patterns ...string) ([]file.Location, error) {
	squashedLocations, err := i.squashed.FilesByGlob(patterns...)
	if err != nil {
		return nil, err
	}

	allLayersLocations, err := i.allLayers.FilesByGlob(patterns...)
	if err != nil {
		return nil, err
	}

	var mergedLocations []file.Location
	for _, l := range squashedLocations {
		mergedLocations = append(mergedLocations, file.Location{
			LocationData: l.LocationData,
			LocationMetadata: file.LocationMetadata{
				Annotations:     l.Annotations,
				IsSquashedLayer: true,
			},
		})
	}

	for _, l := range allLayersLocations {
		mergedLocations = append(mergedLocations, file.Location{
			LocationData: l.LocationData,
			LocationMetadata: file.LocationMetadata{
				Annotations:     l.Annotations,
				IsSquashedLayer: false,
			},
		})
	}

	return mergedLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (i *ContainerImageSquashAllLayers) RelativeFileByPath(location file.Location, path string) *file.Location {
	return i.squashed.RelativeFileByPath(location, path)
}

// FileContentsByLocation fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (i *ContainerImageSquashAllLayers) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	return i.squashed.FileContentsByLocation(location)
}

func (i *ContainerImageSquashAllLayers) FilesByMIMEType(types ...string) ([]file.Location, error) {
	squashedLocations, err := i.squashed.FilesByMIMEType(types...)
	if err != nil {
		return nil, err
	}

	allLayersLocations, err := i.allLayers.FilesByMIMEType(types...)
	if err != nil {
		return nil, err
	}

	var mergedLocations []file.Location
	for _, l := range squashedLocations {
		mergedLocations = append(mergedLocations, file.Location{
			LocationData: l.LocationData,
			LocationMetadata: file.LocationMetadata{
				Annotations:     l.Annotations,
				IsSquashedLayer: true,
			},
		})
	}

	for _, l := range allLayersLocations {
		mergedLocations = append(mergedLocations, file.Location{
			LocationData: l.LocationData,
			LocationMetadata: file.LocationMetadata{
				Annotations:     l.Annotations,
				IsSquashedLayer: false,
			},
		})
	}

	return mergedLocations, nil
}

func (i *ContainerImageSquashAllLayers) AllLocations(ctx context.Context) <-chan file.Location {
	return i.squashed.AllLocations(ctx)
}

func (i *ContainerImageSquashAllLayers) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return i.squashed.FileMetadataByLocation(location)
}
