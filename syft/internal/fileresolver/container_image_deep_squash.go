package fileresolver

import (
	"context"
	"io"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ContainerImageDeepSquash)(nil)

// ContainerImageDeepSquash implements path and content access for the paths in the squashed tree, but with additional
// depth from all layers. The goal of this is to allow for producing results where the first layer which the material
// was added can be annotated in the SBOM (as opposed to the last [visible] layer for the path like with the squashed
// file resolver).
type ContainerImageDeepSquash struct {
	squashed  file.Resolver
	allLayers file.Resolver
}

// NewFromContainerImageDeepSquash returns a new resolver from the perspective of all image layers for the given image.
func NewFromContainerImageDeepSquash(img *image.Image) (*ContainerImageDeepSquash, error) {
	squashed, err := NewFromContainerImageSquash(img)
	if err != nil {
		return nil, err
	}

	allLayers, err := NewFromContainerImageAllLayers(img)
	if err != nil {
		return nil, err
	}

	// we will do the work here to mark visibility with results from two resolvers (don't do the work twice!)
	allLayers.markVisibility = false

	return &ContainerImageDeepSquash{
		squashed:  squashed,
		allLayers: allLayers,
	}, nil
}

// HasPath indicates if the given path exists in the underlying source.
func (i *ContainerImageDeepSquash) HasPath(path string) bool {
	// there is no need to merge results from all layers since path-based results should always be adjusted relative to the squashed tree (which is different when considering layers)
	return i.squashed.HasPath(path)
}

// FilesByPath returns all file.References that match the given paths from any layer in the image.
func (i *ContainerImageDeepSquash) FilesByPath(paths ...string) ([]file.Location, error) {
	squashedLocations, err := i.squashed.FilesByPath(paths...)
	if err != nil {
		return nil, err
	}

	if len(squashedLocations) == 0 {
		// this is meant to return all files in all layers only for paths that are present in the squashed tree. If
		// there are no results from the squashed tree then there are no paths to raise up.
		return nil, nil
	}

	allLayersLocations, err := i.allLayers.FilesByPath(paths...)
	if err != nil {
		return nil, err
	}

	return i.mergeLocations(squashedLocations, allLayersLocations), nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (i *ContainerImageDeepSquash) FilesByGlob(patterns ...string) ([]file.Location, error) {
	squashedLocations, err := i.squashed.FilesByGlob(patterns...)
	if err != nil {
		return nil, err
	}

	if len(squashedLocations) == 0 {
		// this is meant to return all files in all layers only for paths that are present in the squashed tree. If
		// there are no results from the squashed tree then there are no paths to raise up.
		return nil, nil
	}

	allLayersLocations, err := i.allLayers.FilesByGlob(patterns...)
	if err != nil {
		return nil, err
	}

	return i.mergeLocations(squashedLocations, allLayersLocations), nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (i *ContainerImageDeepSquash) RelativeFileByPath(location file.Location, path string) *file.Location {
	if !i.squashed.HasPath(path) {
		return nil
	}

	l := i.squashed.RelativeFileByPath(location, path)
	if l != nil {
		loc := l.WithAnnotation(file.VisibleAnnotationKey, file.VisibleAnnotation)
		return &loc
	}

	l = i.allLayers.RelativeFileByPath(location, path)
	if l != nil {
		loc := l.WithAnnotation(file.VisibleAnnotationKey, file.HiddenAnnotation)
		return &loc
	}
	return nil
}

// FileContentsByLocation fetches file contents for a single file reference.
// If the path does not exist an error is returned.
func (i *ContainerImageDeepSquash) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	// regardless of the layer or scope, if the user gives us a specific path+layer location, then we should always
	// return the contents for that specific location (thus all-layers scope must always be used)
	return i.allLayers.FileContentsByLocation(location)
}

func (i *ContainerImageDeepSquash) FilesByMIMEType(types ...string) ([]file.Location, error) {
	squashedLocations, err := i.squashed.FilesByMIMEType(types...)
	if err != nil {
		return nil, err
	}

	if len(squashedLocations) == 0 {
		// this is meant to return all files in all layers only for paths that are present in the squashed tree. If
		// there are no results from the squashed tree then there are no paths to raise up.
		return nil, nil
	}

	allLayersLocations, err := i.allLayers.FilesByMIMEType(types...)
	if err != nil {
		return nil, err
	}

	return i.mergeLocations(squashedLocations, allLayersLocations), nil
}

func (i *ContainerImageDeepSquash) AllLocations(ctx context.Context) <-chan file.Location {
	return i.mergeLocationStreams(ctx, i.squashed.AllLocations(ctx), i.allLayers.AllLocations(ctx))
}

func (i *ContainerImageDeepSquash) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	// regardless of the layer or scope, if the user gives us a specific path+layer location, then we should always
	// return the metadata for that specific location (thus all-layers scope must always be used)
	return i.allLayers.FileMetadataByLocation(location)
}

func (i *ContainerImageDeepSquash) mergeLocations(squashedLocations, allLayersLocations []file.Location) []file.Location {
	var result []file.Location

	if len(squashedLocations) == 0 {
		// this is meant to return all files in all layers only for paths that are present in the squashed tree. If
		// there are no results from the squashed tree then there are no paths to raise up.
		return nil
	}

	// we are using a location set to deduplicate locations, but we don't use it for the returned
	// results in order to preserve the order of the locations from the underlying filetree query
	squashedCoords := file.NewLocationSet()
	for _, l := range squashedLocations {
		result = append(result, l.WithAnnotation(file.VisibleAnnotationKey, file.VisibleAnnotation))
		squashedCoords.Add(l)
	}

	for _, l := range allLayersLocations {
		if squashedCoords.Contains(l) {
			// this path + layer is already in the squashed tree results, skip it (deduplicate location results)
			continue
		}

		if !i.squashed.HasPath(l.RealPath) {
			// if we find a location for a path that matches the query (e.g. **/node_modules) but is not present in the squashed tree, skip it
			continue
		}

		// not only should the real path to the file exist, but the way we took to get there should also exist
		// (e.g. if we are looking for /etc/passwd, but the real path is /etc/passwd -> /etc/passwd-1, then we should
		// make certain that /etc/passwd-1 exists)
		if l.AccessPath != "" && !i.squashed.HasPath(l.AccessPath) {
			continue
		}

		result = append(result, l.WithAnnotation(file.VisibleAnnotationKey, file.HiddenAnnotation))
	}

	return result
}

func (i *ContainerImageDeepSquash) mergeLocationStreams(ctx context.Context, squashedLocations, allLayersLocations <-chan file.Location) <-chan file.Location {
	result := make(chan file.Location)
	go func() {
		defer close(result)

		// we are using a location set to deduplicate locations, but we don't use it for the returned
		// results in order to preserve the order of the locations from the underlying filetree query
		squashedCoords := file.NewLocationSet()
		var isDone bool
		for l := range squashedLocations {
			if isDone {
				// bleed off the rest of the results from the squashed stream and not leak a goroutine
				continue
			}
			select {
			case <-ctx.Done():
				isDone = true
			default:
				result <- l.WithAnnotation(file.VisibleAnnotationKey, file.VisibleAnnotation)
				squashedCoords.Add(l)
			}
		}

		for l := range allLayersLocations {
			if isDone {
				// bleed off the rest of the results from the squashed stream and not leak a goroutine
				continue
			}

			if squashedCoords.Empty() {
				// this is meant to return all files in all layers only for paths that are present in the squashed tree.
				// If there are no results from the squashed tree, then there are no paths to raise up.
				// That being said, we need to bleed off the rest of the results from the allLayersLocations stream
				// and not leak a goroutine.
				continue
			}

			if squashedCoords.Contains(l) {
				// we've already seen this location from the squashed stream, skip it
				continue
			}

			if !i.squashed.HasPath(l.RealPath) {
				// if we find a location for a path that matches the query (e.g. **/node_modules) but is not present in the squashed tree, skip it
				continue
			}

			// not only should the real path to the file exist, but the way we took to get there should also exist
			// (e.g. if we are looking for /etc/passwd, but the real path is /etc/passwd -> /etc/passwd-1, then we should
			// make certain that /etc/passwd-1 exists)
			if l.AccessPath != "" && !i.squashed.HasPath(l.AccessPath) {
				continue
			}

			select {
			case <-ctx.Done():
				isDone = true
			default:
				result <- l.WithAnnotation(file.VisibleAnnotationKey, file.HiddenAnnotation)
			}
		}
	}()

	return result
}
