package source

import (
	"fmt"
	"io"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

var _ Resolver = (*ImageSquashResolver)(nil)

// ImageSquashResolver implements path and content access for the Squashed source option for container image data sources.
type ImageSquashResolver struct {
	img *image.Image
}

// NewImageSquashResolver returns a new resolver from the perspective of the squashed representation for the given image.
func NewImageSquashResolver(img *image.Image) (*ImageSquashResolver, error) {
	if img.SquashedTree() == nil {
		return nil, fmt.Errorf("the image does not have have a squashed tree")
	}
	return &ImageSquashResolver{img: img}, nil
}

// FilesByPath returns all file.References that match the given paths within the squashed representation of the image.
func (r *ImageSquashResolver) FilesByPath(paths ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, path := range paths {
		tree := r.img.SquashedTree()
		exists, _, ref, err := tree.File(file.Path(path), true)
		if err != nil {
			return nil, err
		}
		if !exists && ref == nil {
			// no file found, keep looking through layers
			continue
		}

		// don't consider directories (special case: there is no path information for /)
		if ref.RealPath == "/" {
			continue
		} else if r.img.FileCatalog.Exists(*ref) {
			metadata, err := r.img.FileCatalog.Get(*ref)
			if err != nil {
				return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", ref.RealPath, err)
			}
			if metadata.Metadata.IsDir {
				continue
			}
		}

		// a file may be a symlink, process it as such and resolve it
		resolvedRef, err := r.img.ResolveLinkByImageSquash(*ref)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve link from img (ref=%+v): %w", ref, err)
		}

		if resolvedRef != nil && !uniqueFileIDs.Contains(*resolvedRef) {
			uniqueFileIDs.Add(*resolvedRef)
			uniqueLocations = append(uniqueLocations, NewLocationFromImage(*resolvedRef, r.img))
		}
	}

	return uniqueLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern within the squashed representation of the image.
func (r *ImageSquashResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, pattern := range patterns {
		results, err := r.img.SquashedTree().FilesByGlob(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve files by glob (%s): %w", pattern, err)
		}

		for _, result := range results {
			// don't consider directories (special case: there is no path information for /)
			if result.Path == "/" {
				continue
			} else if r.img.FileCatalog.Exists(result.Reference) {
				metadata, err := r.img.FileCatalog.Get(result.Reference)
				if err != nil {
					return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", result.Path, err)
				}
				if metadata.Metadata.IsDir {
					continue
				}
			}

			resolvedLocations, err := r.FilesByPath(string(result.Path))
			if err != nil {
				return nil, fmt.Errorf("failed to find files by path (result=%+v): %w", result, err)
			}
			for _, resolvedLocation := range resolvedLocations {
				if !uniqueFileIDs.Contains(resolvedLocation.ref) {
					uniqueFileIDs.Add(resolvedLocation.ref)
					uniqueLocations = append(uniqueLocations, resolvedLocation)
				}
			}
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file. For the
// ImageSquashResolver, this is a simple path lookup.
func (r *ImageSquashResolver) RelativeFileByPath(_ Location, path string) *Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// MultipleFileContentsByLocation returns the file contents for all file.References relative to the image. Note that a
// file.Reference is a path relative to a particular layer, in this case only from the squashed representation.
func (r *ImageSquashResolver) MultipleFileContentsByLocation(locations []Location) (map[Location]io.ReadCloser, error) {
	return mapLocationRefs(r.img.MultipleFileContentsByRef, locations)
}

// FileContentsByLocation fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (r *ImageSquashResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	return r.img.FileContentsByRef(location.ref)
}
