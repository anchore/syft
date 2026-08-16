package fileresolver

import (
	"context"
	"fmt"
	"io"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ContainerImageSquash)(nil)

// ContainerImageSquash implements path and content access for the Squashed source option for container image data sources.
type ContainerImageSquash struct {
	img *image.Image
}

// NewFromContainerImageSquash returns a new resolver from the perspective of the squashed representation for the given image.
func NewFromContainerImageSquash(img *image.Image) (*ContainerImageSquash, error) {
	if img.SquashedTree() == nil {
		return nil, fmt.Errorf("the image does not have have a squashed tree")
	}

	return &ContainerImageSquash{
		img: img,
	}, nil
}

// HasPath indicates if the given path exists in the underlying source.
func (r *ContainerImageSquash) HasPath(path string) bool {
	return r.img.SquashedTree().HasPath(stereoscopeFile.Path(path))
}

// FilesByPath returns all file.References that match the given paths within the squashed representation of the image.
func (r *ContainerImageSquash) FilesByPath(paths ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, path := range paths {
		// if the requested path is itself a hardlink, surface it at its own path (bound to its target's content)
		// rather than collapsing it onto the target's path, so that image results are in parity with directory
		// results (which cannot tell a hardlink from a regular file).
		if ownRef, targetRef, ok := r.hardLinkAtPath(path); ok {
			if !uniqueFileIDs.Contains(ownRef) {
				uniqueFileIDs.Add(ownRef)
				uniqueLocations = append(uniqueLocations, file.NewVirtualLocationFromImage(string(ownRef.RealPath), path, targetRef, r.img))
			}
			continue
		}

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
			if metadata.IsDir() {
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
			uniqueLocations = append(uniqueLocations, file.NewLocationFromImage(path, *resolvedRef.Reference, r.img))
		}
	}

	return uniqueLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern within the squashed representation of the image.
//
//nolint:gocognit
func (r *ContainerImageSquash) FilesByGlob(patterns ...string) ([]file.Location, error) {
	uniqueCoordinates := file.NewCoordinateSet()
	uniqueLocations := make([]file.Location, 0)

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
				if metadata.IsDir() {
					continue
				}
			}
			// TODO: alex: can't we just use the result.Reference here instead?
			resolvedLocations, err := r.FilesByPath(string(result.RequestPath))
			if err != nil {
				return nil, fmt.Errorf("failed to find files by path (result=%+v): %w", result, err)
			}
			for _, resolvedLocation := range resolvedLocations {
				// dedup on the surfaced coordinate rather than the underlying reference: distinct hardlinks share a
				// single target reference but each has its own real path, so a reference-based dedup would collapse
				// them back onto one entry (the exact behavior this parity fix removes). symlink resolutions keep
				// their target's real path, so they still collapse as before.
				if uniqueCoordinates.Contains(resolvedLocation.Coordinates) {
					continue
				}
				uniqueCoordinates.Add(resolvedLocation.Coordinates)
				uniqueLocations = append(uniqueLocations, resolvedLocation)
			}
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file. For the
// ContainerImageSquash, this is a simple path lookup.
func (r *ContainerImageSquash) RelativeFileByPath(_ file.Location, path string) *file.Location {
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
func (r *ContainerImageSquash) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	entry, err := r.img.FileCatalog.Get(location.Reference())
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for path=%q from file catalog: %w", location.RealPath, err)
	}

	switch entry.Type {
	case stereoscopeFile.TypeSymLink, stereoscopeFile.TypeHardLink:
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
	case stereoscopeFile.TypeDirectory:
		return nil, fmt.Errorf("unable to get file contents for directory: %+v", location)
	}

	return r.img.OpenReference(location.Reference())
}

func (r *ContainerImageSquash) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, ref := range r.img.SquashedTree().AllFiles(stereoscopeFile.AllTypes()...) {
			loc := file.NewLocationFromImage(string(ref.RealPath), ref, r.img)
			// surface a hardlink as the underlying type it points to (at its own path) so image results match
			// directory results, which cannot distinguish a hardlink from a regular file.
			if targetRef, ok := r.resolveHardLinkTarget(ref); ok {
				loc = file.NewVirtualLocationFromImage(string(ref.RealPath), string(ref.RealPath), targetRef, r.img)
			}
			select {
			case <-ctx.Done():
				return
			case results <- loc:
				continue
			}
		}
	}()
	return results
}

// hardLinkAtPath returns the hardlink's own reference and its resolved target reference when the basename of path is a
// hardlink. ok is false when path does not exist or is not a hardlink. The lookup does not follow the basename link so
// that the hardlink's own path is preserved. This adds a tree walk per FilesByPath path; if it shows up in
// profiles, fold the hardlink check into the existing SearchByPath resolution.
func (r *ContainerImageSquash) hardLinkAtPath(path string) (stereoscopeFile.Reference, stereoscopeFile.Reference, bool) {
	var own stereoscopeFile.Reference
	exists, resolution, err := r.img.SquashedTree().File(stereoscopeFile.Path(path))
	if err != nil || !exists || !resolution.HasReference() {
		return own, own, false
	}
	target, ok := r.resolveHardLinkTarget(*resolution.Reference)
	if !ok {
		return own, own, false
	}
	return *resolution.Reference, target, true
}

// resolveHardLinkTarget returns the reference of a hardlink's underlying target when ref is a hardlink; ok is false
// otherwise. No resolution is performed for non-hardlinks (symlinks keep their existing resolution semantics).
func (r *ContainerImageSquash) resolveHardLinkTarget(ref stereoscopeFile.Reference) (stereoscopeFile.Reference, bool) {
	metadata, err := r.img.FileCatalog.Get(ref)
	if err != nil || metadata.Type != stereoscopeFile.TypeHardLink {
		return ref, false
	}
	resolved, err := r.img.ResolveLinkByImageSquash(ref)
	if err != nil || !resolved.HasReference() {
		return ref, false
	}
	return *resolved.Reference, true
}

func (r *ContainerImageSquash) FilesByMIMEType(types ...string) ([]file.Location, error) {
	refs, err := r.img.SquashedSearchContext.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}

	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, ref := range refs {
		if ref.HasReference() {
			if uniqueFileIDs.Contains(*ref.Reference) {
				continue
			}
			location := file.NewLocationFromImage(string(ref.RequestPath), *ref.Reference, r.img)

			uniqueFileIDs.Add(*ref.Reference)
			uniqueLocations = append(uniqueLocations, location)
		}
	}

	return uniqueLocations, nil
}

func (r *ContainerImageSquash) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return fileMetadataByLocation(r.img, location)
}
