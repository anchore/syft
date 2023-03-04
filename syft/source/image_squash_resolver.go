package source

import (
	"fmt"
	"io"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
)

var _ FileResolver = (*imageSquashResolver)(nil)

// imageSquashResolver implements path and content access for the Squashed source option for container image data sources.
type imageSquashResolver struct {
	img *image.Image
}

// newImageSquashResolver returns a new resolver from the perspective of the squashed representation for the given image.
func newImageSquashResolver(img *image.Image) (*imageSquashResolver, error) {
	if img.SquashedTree() == nil {
		return nil, fmt.Errorf("the image does not have have a squashed tree")
	}

	return &imageSquashResolver{
		img: img,
	}, nil
}

// HasPath indicates if the given path exists in the underlying source.
func (r *imageSquashResolver) HasPath(path string) bool {
	return r.img.SquashedTree().HasPath(file.Path(path))
}

// FilesByPath returns all file.References that match the given paths within the squashed representation of the image.
func (r *imageSquashResolver) FilesByPath(paths ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, path := range paths {
		ref, err := r.img.SquashedSearchContext.SearchByPath(path, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		if !ref.HasReference() {
			// no file found, keep looking through layers
			continue
		}

		// don't consider directories (special case: there is no path information for /)
		if ref.RealPath == "/" {
			continue
		} else if r.img.FileCatalog.Exists(*ref.Reference) {
			metadata, err := r.img.FileCatalog.Get(*ref.Reference)
			if err != nil {
				return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", ref.RealPath, err)
			}
			// don't consider directories
			if metadata.Metadata.IsDir {
				continue
			}
		}

		// a file may be a symlink, process it as such and resolve it
		resolvedRef, err := r.img.ResolveLinkByImageSquash(*ref.Reference)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve link from img (ref=%+v): %w", ref, err)
		}

		if resolvedRef.HasReference() && !uniqueFileIDs.Contains(*resolvedRef.Reference) {
			uniqueFileIDs.Add(*resolvedRef.Reference)
			uniqueLocations = append(uniqueLocations, NewLocationFromImage(path, *resolvedRef.Reference, r.img))
		}
	}

	return uniqueLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern within the squashed representation of the image.
// nolint:gocognit
func (r *imageSquashResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, pattern := range patterns {
		results, err := r.img.SquashedSearchContext.SearchByGlob(pattern, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve files by glob (%s): %w", pattern, err)
		}

		for _, result := range results {
			if !result.HasReference() {
				continue
			}
			// don't consider directories (special case: there is no path information for /)
			if result.RealPath == "/" {
				continue
			}

			if r.img.FileCatalog.Exists(*result.Reference) {
				metadata, err := r.img.FileCatalog.Get(*result.Reference)
				if err != nil {
					return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", result.RequestPath, err)
				}
				// don't consider directories
				if metadata.Metadata.IsDir {
					continue
				}
			}
			// TODO: alex: can't we just use the result.Reference here instead?
			resolvedLocations, err := r.FilesByPath(string(result.RequestPath))
			if err != nil {
				return nil, fmt.Errorf("failed to find files by path (result=%+v): %w", result, err)
			}
			for _, resolvedLocation := range resolvedLocations {
				if uniqueFileIDs.Contains(resolvedLocation.ref) {
					continue
				}
				uniqueFileIDs.Add(resolvedLocation.ref)
				uniqueLocations = append(uniqueLocations, resolvedLocation)
			}
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file. For the
// imageSquashResolver, this is a simple path lookup.
func (r *imageSquashResolver) RelativeFileByPath(_ Location, path string) *Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// FileContentsByLocation fetches file contents for a single file reference, regardless of the source layer.
// If the path does not exist an error is returned.
func (r *imageSquashResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	entry, err := r.img.FileCatalog.Get(location.ref)
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for path=%q from file catalog: %w", location.RealPath, err)
	}

	switch entry.Metadata.Type {
	case file.TypeSymLink, file.TypeHardLink:
		// the location we are searching may be a symlink, we should always work with the resolved file
		locations, err := r.FilesByPath(location.RealPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve content location at location=%+v: %w", location, err)
		}

		switch len(locations) {
		case 0:
			return nil, fmt.Errorf("link resolution failed while resolving content location: %+v", location)
		case 1:
			location = locations[0]
		default:
			return nil, fmt.Errorf("link resolution resulted in multiple results while resolving content location: %+v", location)
		}
	case file.TypeDirectory:
		return nil, fmt.Errorf("unable to get file contents for directory: %+v", location)
	}

	return r.img.FileContentsByRef(location.ref)
}

func (r *imageSquashResolver) AllLocations() <-chan Location {
	results := make(chan Location)
	go func() {
		defer close(results)
		for _, ref := range r.img.SquashedTree().AllFiles(file.AllTypes()...) {
			results <- NewLocationFromImage(string(ref.RealPath), ref, r.img)
		}
	}()
	return results
}

func (r *imageSquashResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	refs, err := r.img.SquashedSearchContext.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}

	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, ref := range refs {
		if ref.HasReference() {
			if uniqueFileIDs.Contains(*ref.Reference) {
				continue
			}
			location := NewLocationFromImage(string(ref.RequestPath), *ref.Reference, r.img)

			uniqueFileIDs.Add(*ref.Reference)
			uniqueLocations = append(uniqueLocations, location)
		}
	}

	return uniqueLocations, nil
}

func (r *imageSquashResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	return fileMetadataByLocation(r.img, location)
}
