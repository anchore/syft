package source

import (
	"github.com/anchore/stereoscope/pkg/image"
	"io"
)

var _ FileResolver = (*imageSquashWithAllLayersResolver)(nil)

// imageSquashWithAllLayersResolver acts like a squash resolver, but additionally returns all paths in earlier layers
// that have been added/modified (like the all-layers resolver).
type imageSquashWithAllLayersResolver struct {
	squashed  *imageSquashResolver
	allLayers *imageAllLayersResolver
}

// newImageSquashWithAllLayersResolver returns a new resolver from the perspective of the squashed representation for
// the given image, but additionally returns all instances of a path that have been added/modified.
func newImageSquashWithAllLayersResolver(img *image.Image) (*imageSquashWithAllLayersResolver, error) {
	squashed, err := newImageSquashResolver(img)
	if err != nil {
		return nil, err
	}

	allLayers, err := newImageAllLayersResolver(img)
	if err != nil {
		return nil, err
	}

	return &imageSquashWithAllLayersResolver{
		squashed:  squashed,
		allLayers: allLayers,
	}, nil
}

func (i imageSquashWithAllLayersResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	return i.squashed.FileContentsByLocation(location)
}

func (i imageSquashWithAllLayersResolver) HasPath(s string) bool {
	return i.squashed.HasPath(s)
}

func (i imageSquashWithAllLayersResolver) filterLocations(locations []Location, err error) ([]Location, error) {
	if err != nil {
		return locations, err
	}
	var ret []Location
	for _, l := range locations {
		if i.squashed.HasPath(l.RealPath) {
			// not only should the real path to the file exist, but the way we took to get there should also exist
			// (e.g. if we are looking for /etc/passwd, but the real path is /etc/passwd -> /etc/passwd-1, then we should
			// make certain that /etc/passwd-1 exists)
			if l.VirtualPath != "" && !i.squashed.HasPath(l.VirtualPath) {
				continue
			}
			ret = append(ret, l)
		}
	}
	return ret, nil
}

func (i imageSquashWithAllLayersResolver) FilesByPath(paths ...string) ([]Location, error) {
	return i.filterLocations(i.allLayers.FilesByPath(paths...))
}

func (i imageSquashWithAllLayersResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	return i.filterLocations(i.allLayers.FilesByGlob(patterns...))
}

func (i imageSquashWithAllLayersResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	return i.filterLocations(i.allLayers.FilesByMIMEType(types...))
}

func (i imageSquashWithAllLayersResolver) RelativeFileByPath(l Location, path string) *Location {
	if !i.squashed.HasPath(path) {
		return nil
	}
	return i.allLayers.RelativeFileByPath(l, path)
}

func (i imageSquashWithAllLayersResolver) AllLocations() <-chan Location {
	var ret = make(chan Location)
	go func() {
		defer close(ret)
		for l := range i.allLayers.AllLocations() {
			if i.squashed.HasPath(l.RealPath) {
				ret <- l
			}
		}
	}()

	return ret
}

func (i imageSquashWithAllLayersResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	return fileMetadataByLocation(i.squashed.img, location)
}
