package resolvers

import (
	"archive/tar"
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

// AllLayersResolver implements path and content access for the AllLayers scope option for container image data sources.
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
		// we should search all possible resolutions within the valid scope
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
func (r *AllLayersResolver) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueFiles := make([]file.Reference, 0)

	for _, path := range paths {
		for idx, layerIdx := range r.layers {
			ref := r.img.Layers[layerIdx].Tree.File(path)
			if ref == nil {
				// no file found, keep looking through layers
				continue
			}

			results, err := r.fileByRef(*ref, uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			uniqueFiles = append(uniqueFiles, results...)
		}
	}

	return uniqueFiles, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
func (r *AllLayersResolver) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueFiles := make([]file.Reference, 0)

	for _, pattern := range patterns {
		for idx, layerIdx := range r.layers {
			refs, err := r.img.Layers[layerIdx].Tree.FilesByGlob(pattern)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve files by glob (%s): %w", pattern, err)
			}

			for _, ref := range refs {
				results, err := r.fileByRef(ref, uniqueFileIDs, idx)
				if err != nil {
					return nil, err
				}
				uniqueFiles = append(uniqueFiles, results...)
			}
		}
	}

	return uniqueFiles, nil
}

// MultipleFileContentsByRef returns the file contents for all file.References relative to the image. Note that a
// file.Reference is a path relative to a particular layer.
func (r *AllLayersResolver) MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error) {
	return r.img.MultipleFileContentsByRef(f...)
}
