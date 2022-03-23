package source

import (
	"archive/tar"
	"fmt"
	"io"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*imageSquashResolver)(nil)

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
	return r.img.SquashedTree().HasPath(stereoscopeFile.Path(path))
}

// FilesByPath returns all stereoscopeFile.References that match the given paths within the squashed representation of the image.
func (r *imageSquashResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, path := range paths {
		tree := r.img.SquashedTree()
		_, ref, err := tree.File(stereoscopeFile.Path(path), filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		if ref == nil {
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
			uniqueLocations = append(uniqueLocations, file.NewLocationFromImage(path, *resolvedRef, r.img))
		}
	}

	return uniqueLocations, nil
}

// FilesByGlob returns all stereoscopeFile.References that match the given path glob pattern within the squashed representation of the image.
func (r *imageSquashResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, pattern := range patterns {
		results, err := r.img.SquashedTree().FilesByGlob(pattern, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve files by glob (%s): %w", pattern, err)
		}

		for _, result := range results {
			// don't consider directories (special case: there is no path information for /)
			if result.MatchPath == "/" {
				continue
			}

			if r.img.FileCatalog.Exists(result.Reference) {
				metadata, err := r.img.FileCatalog.Get(result.Reference)
				if err != nil {
					return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", result.MatchPath, err)
				}
				if metadata.Metadata.IsDir {
					continue
				}
			}

			resolvedLocations, err := r.FilesByPath(string(result.MatchPath))
			if err != nil {
				return nil, fmt.Errorf("failed to find files by path (result=%+v): %w", result, err)
			}
			for _, resolvedLocation := range resolvedLocations {
				if !uniqueFileIDs.Contains(resolvedLocation.Ref()) {
					uniqueFileIDs.Add(resolvedLocation.Ref())
					uniqueLocations = append(uniqueLocations, resolvedLocation)
				}
			}
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another stereoscopeFile. For the
// imageSquashResolver, this is a simple path lookup.
func (r *imageSquashResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// FileContentsByLocation fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (r *imageSquashResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	entry, err := r.img.FileCatalog.Get(location.Ref())
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for path=%q from file catalog: %w", location.RealPath, err)
	}

	switch entry.Metadata.TypeFlag {
	case tar.TypeSymlink, tar.TypeLink:
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
	}

	return r.img.FileContentsByRef(location.Ref())
}

func (r *imageSquashResolver) AllLocations() <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, ref := range r.img.SquashedTree().AllFiles(stereoscopeFile.AllTypes...) {
			results <- file.NewLocationFromImage(string(ref.RealPath), ref, r.img)
		}
	}()
	return results
}

func (r *imageSquashResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	refs, err := r.img.FilesByMIMETypeFromSquash(types...)
	if err != nil {
		return nil, err
	}

	var locations []file.Location
	for _, ref := range refs {
		locations = append(locations, file.NewLocationFromImage(string(ref.RealPath), ref, r.img))
	}

	return locations, nil
}

func (r *imageSquashResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return fileMetadataByImageLocation(r.img, location)
}
