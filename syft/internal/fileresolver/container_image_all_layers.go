package fileresolver

import (
	"fmt"
	"io"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ContainerImageAllLayers)(nil)

// ContainerImageAllLayers implements path and content access for the AllLayers source option for container image data sources.
type ContainerImageAllLayers struct {
	img    *image.Image
	layers []int
}

// NewFromContainerImageAllLayers returns a new resolver from the perspective of all image layers for the given image.
func NewFromContainerImageAllLayers(img *image.Image) (*ContainerImageAllLayers, error) {
	if len(img.Layers) == 0 {
		return nil, fmt.Errorf("the image does not contain any layers")
	}

	var layers = make([]int, 0)
	for idx := range img.Layers {
		layers = append(layers, idx)
	}
	return &ContainerImageAllLayers{
		img:    img,
		layers: layers,
	}, nil
}

// HasPath indicates if the given path exists in the underlying source.
func (r *ContainerImageAllLayers) HasPath(path string) bool {
	p := stereoscopeFile.Path(path)
	for _, layerIdx := range r.layers {
		tree := r.img.Layers[layerIdx].Tree
		if tree.HasPath(p) {
			return true
		}
	}
	return false
}

func (r *ContainerImageAllLayers) fileByRef(ref stereoscopeFile.Reference, uniqueFileIDs stereoscopeFile.ReferenceSet, layerIdx int) ([]stereoscopeFile.Reference, error) {
	uniqueFiles := make([]stereoscopeFile.Reference, 0)

	// since there is potentially considerable work for each symlink/hardlink that needs to be resolved, let's check to see if this is a symlink/hardlink first
	entry, err := r.img.FileCatalog.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch metadata (ref=%+v): %w", ref, err)
	}

	if entry.Metadata.Type == stereoscopeFile.TypeHardLink || entry.Metadata.Type == stereoscopeFile.TypeSymLink {
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
func (r *ContainerImageAllLayers) FilesByPath(paths ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, path := range paths {
		for idx, layerIdx := range r.layers {
			ref, err := r.img.Layers[layerIdx].SearchContext.SearchByPath(path, filetree.FollowBasenameLinks, filetree.DoNotFollowDeadBasenameLinks)
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
				if metadata.Metadata.IsDir() {
					continue
				}
			}

			results, err := r.fileByRef(*ref.Reference, uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			for _, result := range results {
				uniqueLocations = append(uniqueLocations, file.NewLocationFromImage(path, result, r.img))
			}
		}
	}
	return uniqueLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
// nolint:gocognit
func (r *ContainerImageAllLayers) FilesByGlob(patterns ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, pattern := range patterns {
		for idx, layerIdx := range r.layers {
			results, err := r.img.Layers[layerIdx].SquashedSearchContext.SearchByGlob(pattern, filetree.FollowBasenameLinks, filetree.DoNotFollowDeadBasenameLinks)
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
				} else if r.img.FileCatalog.Exists(*result.Reference) {
					metadata, err := r.img.FileCatalog.Get(*result.Reference)
					if err != nil {
						return nil, fmt.Errorf("unable to get file metadata for path=%q: %w", result.RequestPath, err)
					}
					// don't consider directories
					if metadata.Metadata.IsDir() {
						continue
					}
				}

				refResults, err := r.fileByRef(*result.Reference, uniqueFileIDs, idx)
				if err != nil {
					return nil, err
				}
				for _, refResult := range refResults {
					uniqueLocations = append(uniqueLocations, file.NewLocationFromImage(string(result.RequestPath), refResult, r.img))
				}
			}
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (r *ContainerImageAllLayers) RelativeFileByPath(location file.Location, path string) *file.Location {
	layer := r.img.FileCatalog.Layer(location.Reference())

	exists, relativeRef, err := layer.SquashedTree.File(stereoscopeFile.Path(path), filetree.FollowBasenameLinks)
	if err != nil {
		log.Errorf("failed to find path=%q in squash: %+w", path, err)
		return nil
	}
	if !exists && !relativeRef.HasReference() {
		return nil
	}

	relativeLocation := file.NewLocationFromImage(path, *relativeRef.Reference, r.img)

	return &relativeLocation
}

// FileContentsByLocation fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (r *ContainerImageAllLayers) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	entry, err := r.img.FileCatalog.Get(location.Reference())
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for path=%q from file catalog: %w", location.RealPath, err)
	}

	switch entry.Metadata.Type {
	case stereoscopeFile.TypeSymLink, stereoscopeFile.TypeHardLink:
		// the location we are searching may be a symlink, we should always work with the resolved file
		newLocation := r.RelativeFileByPath(location, location.AccessPath)
		if newLocation == nil {
			// this is a dead link
			return nil, fmt.Errorf("no contents for location=%q", location.AccessPath)
		}
		location = *newLocation
	case stereoscopeFile.TypeDirectory:
		return nil, fmt.Errorf("cannot read contents of non-file %q", location.Reference().RealPath)
	}

	return r.img.OpenReference(location.Reference())
}

func (r *ContainerImageAllLayers) FilesByMIMEType(types ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for idx, layerIdx := range r.layers {
		refs, err := r.img.Layers[layerIdx].SearchContext.SearchByMIMEType(types...)
		if err != nil {
			return nil, err
		}

		for _, ref := range refs {
			if !ref.HasReference() {
				continue
			}

			refResults, err := r.fileByRef(*ref.Reference, uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			for _, refResult := range refResults {
				uniqueLocations = append(uniqueLocations, file.NewLocationFromImage(string(ref.RequestPath), refResult, r.img))
			}
		}
	}

	return uniqueLocations, nil
}

func (r *ContainerImageAllLayers) AllLocations() <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, layerIdx := range r.layers {
			tree := r.img.Layers[layerIdx].Tree
			for _, ref := range tree.AllFiles(stereoscopeFile.AllTypes()...) {
				results <- file.NewLocationFromImage(string(ref.RealPath), ref, r.img)
			}
		}
	}()
	return results
}

func (r *ContainerImageAllLayers) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return fileMetadataByLocation(r.img, location)
}
