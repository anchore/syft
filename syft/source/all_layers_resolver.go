package source

import (
	"archive/tar"
	"fmt"
	"io"

	"github.com/anchore/stereoscope/pkg/filetree"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

var _ Resolver = (*AllLayersResolver)(nil)

// AllLayersResolver implements path and content access for the AllLayers source option for container image data sources.
type AllLayersResolver struct {
	img    *image.Image
	layers []int
}

// NewAllLayersResolver returns a new resolver from the perspective of all image layers for the given image.
func NewAllLayersResolver(img *image.Image) (*AllLayersResolver, error) {
	if len(img.Layers) == 0 {
		return nil, fmt.Errorf("the image does not contain any layers")
	}

	var layers = make([]int, 0)
	for idx := range img.Layers {
		layers = append(layers, idx)
	}
	return &AllLayersResolver{
		img:    img,
		layers: layers,
	}, nil
}

func (r *AllLayersResolver) fileByRef(ref file.Reference, uniqueFileIDs file.ReferenceSet, layerIdx int) ([]file.Reference, error) {
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
			if resolvedRef != nil && !uniqueFileIDs.Contains(*resolvedRef) {
				uniqueFileIDs.Add(*resolvedRef)
				uniqueFiles = append(uniqueFiles, *resolvedRef)
			}
		}
	} else if !uniqueFileIDs.Contains(ref) {
		uniqueFileIDs.Add(ref)
		uniqueFiles = append(uniqueFiles, ref)
	}

	return uniqueFiles, nil
}

// FilesByPath returns all file.References that match the given paths from any layer in the image.
func (r *AllLayersResolver) FilesByPath(paths ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, path := range paths {
		for idx, layerIdx := range r.layers {
			tree := r.img.Layers[layerIdx].Tree
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

			results, err := r.fileByRef(*ref, uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			for _, result := range results {
				uniqueLocations = append(uniqueLocations, NewLocationFromImage(result, r.img))
			}
		}
	}
	return uniqueLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
// nolint:gocognit
func (r *AllLayersResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueLocations := make([]Location, 0)

	for _, pattern := range patterns {
		for idx, layerIdx := range r.layers {
			results, err := r.img.Layers[layerIdx].Tree.FilesByGlob(pattern, filetree.GlobDoNotFollowDeadBasenameLinks)
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
						return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", result.Path, err)
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
					uniqueLocations = append(uniqueLocations, NewLocationFromImage(refResult, r.img))
				}
			}
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (r *AllLayersResolver) RelativeFileByPath(location Location, path string) *Location {
	entry, err := r.img.FileCatalog.Get(location.ref)
	if err != nil {
		return nil
	}

	exists, _, relativeRef, err := entry.Layer.SquashedTree.File(file.Path(path), true)
	if err != nil {
		log.Errorf("failed to find path=%q in squash: %+w", path, err)
		return nil
	}
	if !exists && relativeRef == nil {
		return nil
	}

	relativeLocation := NewLocationFromImage(*relativeRef, r.img)

	return &relativeLocation
}

// MultipleFileContentsByLocation returns the file contents for all file.References relative to the image. Note that a
// file.Reference is a path relative to a particular layer.
func (r *AllLayersResolver) MultipleFileContentsByLocation(locations []Location) (map[Location]io.ReadCloser, error) {
	return mapLocationRefs(r.img.MultipleFileContentsByRef, locations)
}

// FileContentsByLocation fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (r *AllLayersResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	return r.img.FileContentsByRef(location.ref)
}

type multiContentFetcher func(refs ...file.Reference) (map[file.Reference]io.ReadCloser, error)

func mapLocationRefs(callback multiContentFetcher, locations []Location) (map[Location]io.ReadCloser, error) {
	var fileRefs = make([]file.Reference, len(locations))
	var locationByRefs = make(map[file.Reference]Location)
	var results = make(map[Location]io.ReadCloser)

	for i, location := range locations {
		locationByRefs[location.ref] = location
		fileRefs[i] = location.ref
	}

	contentsByRef, err := callback(fileRefs...)
	if err != nil {
		return nil, err
	}

	for ref, content := range contentsByRef {
		results[locationByRefs[ref]] = content
	}
	return results, nil
}
