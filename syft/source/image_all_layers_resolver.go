package source

import (
	"archive/tar"
	"fmt"
	"io"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
)

var _ FileResolver = (*imageAllLayersResolver)(nil)

// imageAllLayersResolver implements path and content access for the AllLayers source option for container image data sources.
type imageAllLayersResolver struct {
	img    *image.Image
	layers []int
}

// newAllLayersResolver returns a new resolver from the perspective of all image layers for the given image.
func newAllLayersResolver(img *image.Image) (*imageAllLayersResolver, error) {
	if len(img.Layers) == 0 {
		return nil, fmt.Errorf("the image does not contain any layers")
	}

	var layers = make([]int, 0)
	for idx := range img.Layers {
		layers = append(layers, idx)
	}
	return &imageAllLayersResolver{
		img:    img,
		layers: layers,
	}, nil
}

// HasPath indicates if the given path exists in the underlying source.
func (r *imageAllLayersResolver) HasPath(path string) bool {
	p := file.Path(path)
	for _, layerIdx := range r.layers {
		tree := r.img.Layers[layerIdx].Tree
		if tree.HasPath(p) {
			return true
		}
	}
	return false
}

func (r *imageAllLayersResolver) fileByRef(ref file.Reference, uniqueFileIDs file.ReferenceSet, layerIdx int) ([]file.Reference, error) {
	uniqueFiles := make([]file.Reference, 0)

	// since there is potentially considerable work for each symlink/hardlink that needs to be resolved, let's check to see if this is a symlink/hardlink first
	entry, err := r.img.FileCatalog.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch metadata (ref=%+v): %w", ref, err)
	}

	if entry.Metadata.TypeFlag == tar.TypeLink || entry.Metadata.TypeFlag == tar.TypeSymlink {
		// a link may resolve in this layer or higher, assuming a squashed tree is used to search
		// we should search all possible resolutions within the valid source
		for _, subLayerIdx := range r.layers[layerIdx:] {
			resolvedRef, err := r.img.ResolveLinkByLayerSquash(ref, subLayerIdx)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve link from layer (layer=%d ref=%+v): %w", subLayerIdx, ref, err)
			}
			if resolvedRef.HasReference() && !uniqueFileIDs.Contains(*resolvedRef.Reference) {
				uniqueFileIDs.Add(*resolvedRef.Reference)
				uniqueFiles = append(uniqueFiles, *resolvedRef.Reference)
			}
		}
	} else if !uniqueFileIDs.Contains(ref) {
		uniqueFileIDs.Add(ref)
		uniqueFiles = append(uniqueFiles, ref)
	}

	return uniqueFiles, nil
}

// FilesByPath returns all file.References that match the given paths from any layer in the image.
func (r *imageAllLayersResolver) FilesByPath(paths ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, path := range paths {
		for idx, layerIdx := range r.layers {
			tree := r.img.Layers[layerIdx].Tree
			_, ref, err := tree.File(file.Path(path), filetree.FollowBasenameLinks, filetree.DoNotFollowDeadBasenameLinks)
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
				if metadata.Metadata.IsDir {
					continue
				}
			}

			results, err := r.fileByRef(*ref.Reference, uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			for _, result := range results {
				uniqueLocations = append(uniqueLocations, NewLocationFromImage(path, result, r.img))
			}
		}
	}
	return uniqueLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r *imageAllLayersResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, pattern := range patterns {
		for idx, layerIdx := range r.layers {
			results, err := r.img.Layers[layerIdx].SquashedTree.FilesByGlob(pattern, filetree.FollowBasenameLinks, filetree.DoNotFollowDeadBasenameLinks)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve files by glob (%s): %w", pattern, err)
			}

			for _, result := range results {
				// don't consider directories (special case: there is no path information for /)
				if result.RealPath == "/" {
					continue
				} else if r.img.FileCatalog.Exists(result.Reference) {
					metadata, err := r.img.FileCatalog.Get(result.Reference)
					if err != nil {
						return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", result.MatchPath, err)
					}
					if metadata.Metadata.IsDir {
						continue
					}
				}

				refResults, err := r.fileByRef(result.Reference, uniqueFileIDs, idx)
				if err != nil {
					return nil, err
				}
				for _, refResult := range refResults {
					uniqueLocations = append(uniqueLocations, NewLocationFromImage(string(result.MatchPath), refResult, r.img))
				}
			}
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (r *imageAllLayersResolver) RelativeFileByPath(location Location, path string) *Location {
	entry, err := r.img.FileCatalog.Get(location.ref)
	if err != nil {
		return nil
	}

	exists, relativeRef, err := entry.Layer.SquashedTree.File(file.Path(path), filetree.FollowBasenameLinks)
	if err != nil {
		log.Errorf("failed to find path=%q in squash: %+w", path, err)
		return nil
	}
	if !exists && !relativeRef.HasReference() {
		return nil
	}

	relativeLocation := NewLocationFromImage(path, *relativeRef.Reference, r.img)

	return &relativeLocation
}

// FileContentsByLocation fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (r *imageAllLayersResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	entry, err := r.img.FileCatalog.Get(location.ref)
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for path=%q from file catalog: %w", location.RealPath, err)
	}

	switch entry.Metadata.TypeFlag {
	case tar.TypeSymlink, tar.TypeLink:
		// the location we are searching may be a symlink, we should always work with the resolved file
		newLocation := r.RelativeFileByPath(location, location.VirtualPath)
		if newLocation == nil {
			// this is a dead link
			return nil, fmt.Errorf("no contents for location=%q", location.VirtualPath)
		}
		location = *newLocation
	}

	return r.img.FileContentsByRef(location.ref)
}

func (r *imageAllLayersResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	var locations []Location
	for _, layerIdx := range r.layers {
		layer := r.img.Layers[layerIdx]

		refs, err := layer.FilesByMIMEType(types...)
		if err != nil {
			return nil, err
		}

		for _, ref := range refs {
			if ref.HasReference() {
				locations = append(locations, NewLocationFromImage(string(ref.RealPath), *ref.Reference, r.img))
			}
		}
	}

	return locations, nil
}

func (r *imageAllLayersResolver) FilesByExtension(extensions ...string) ([]Location, error) {
	var locations []Location
	for _, extension := range extensions {
		for _, layerIdx := range r.layers {
			layer := r.img.Layers[layerIdx]

			refs, err := layer.FilesByExtension(extension)
			if err != nil {
				return nil, err
			}

			for _, ref := range refs {
				if ref.HasReference() {
					locations = append(locations, NewLocationFromImage(string(ref.RealPath), *ref.Reference, r.img))
				}
			}
		}
	}

	return locations, nil
}

func (r *imageAllLayersResolver) FilesByBasename(filenames ...string) ([]Location, error) {
	var locations []Location
	for _, filename := range filenames {
		for _, layerIdx := range r.layers {
			layer := r.img.Layers[layerIdx]

			refs, err := layer.FilesByBasename(filename)
			if err != nil {
				return nil, err
			}

			for _, ref := range refs {
				if ref.HasReference() {
					locations = append(locations, NewLocationFromImage(string(ref.RealPath), *ref.Reference, r.img))
				}
			}
		}
	}

	return locations, nil
}

func (r *imageAllLayersResolver) FilesByBasenameGlob(globs ...string) ([]Location, error) {
	var locations []Location
	for _, glob := range globs {
		for _, layerIdx := range r.layers {
			layer := r.img.Layers[layerIdx]

			refs, err := layer.FilesByBasenameGlob(glob)
			if err != nil {
				return nil, err
			}

			for _, ref := range refs {
				if ref.HasReference() {
					locations = append(locations, NewLocationFromImage(string(ref.RealPath), *ref.Reference, r.img))
				}
			}
		}
	}

	return locations, nil
}

func (r *imageAllLayersResolver) AllLocations() <-chan Location {
	results := make(chan Location)
	go func() {
		defer close(results)
		for _, layerIdx := range r.layers {
			tree := r.img.Layers[layerIdx].Tree
			for _, ref := range tree.AllFiles(file.AllTypes...) {
				results <- NewLocationFromImage(string(ref.RealPath), ref, r.img)
			}
		}
	}()
	return results
}

func (r *imageAllLayersResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	return fileMetadataByLocation(r.img, location)
}
