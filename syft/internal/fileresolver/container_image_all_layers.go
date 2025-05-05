package fileresolver

import (
	"context"
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
	img            *image.Image
	layers         []int
	markVisibility bool
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
		// This is the entrypoint for the user-facing implementation, which should always annotate locations.
		// We have other resolvers that use this implementation that are already responsible
		// for marking visibility, so we don't need to do it all of the time (a small performance optimization).
		markVisibility: true,
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

	if entry.Type == stereoscopeFile.TypeHardLink || entry.Type == stereoscopeFile.TypeSymLink {
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
				if metadata.IsDir() {
					continue
				}
			}

			results, err := r.fileByRef(*ref.Reference, uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			for _, result := range results {
				l := file.NewLocationFromImage(path, result, r.img)
				r.annotateLocation(&l)
				uniqueLocations = append(uniqueLocations, l)
			}
		}
	}
	return uniqueLocations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern from any layer in the image.
//
//nolint:gocognit
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
					if metadata.IsDir() {
						continue
					}
				}

				refResults, err := r.fileByRef(*result.Reference, uniqueFileIDs, idx)
				if err != nil {
					return nil, err
				}
				for _, refResult := range refResults {
					l := file.NewLocationFromImage(string(result.RequestPath), refResult, r.img)
					r.annotateLocation(&l)
					uniqueLocations = append(uniqueLocations, l)
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
		log.Errorf("failed to find path=%q in squash: %+v", path, err)
		return nil
	}
	if !exists && !relativeRef.HasReference() {
		return nil
	}

	relativeLocation := file.NewLocationFromImage(path, *relativeRef.Reference, r.img)
	r.annotateLocation(&relativeLocation)

	return &relativeLocation
}

// FileContentsByLocation fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (r *ContainerImageAllLayers) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	entry, err := r.img.FileCatalog.Get(location.Reference())
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for path=%q from file catalog: %w", location.RealPath, err)
	}

	switch entry.Type {
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
				l := file.NewLocationFromImage(string(ref.RequestPath), refResult, r.img)
				r.annotateLocation(&l)
				uniqueLocations = append(uniqueLocations, l)
			}
		}
	}

	return uniqueLocations, nil
}

func (r *ContainerImageAllLayers) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, layerIdx := range r.layers {
			tree := r.img.Layers[layerIdx].Tree
			for _, ref := range tree.AllFiles(stereoscopeFile.AllTypes()...) {
				l := file.NewLocationFromImage(string(ref.RealPath), ref, r.img)
				r.annotateLocation(&l)
				select {
				case <-ctx.Done():
					return
				case results <- l:
					continue
				}
			}
		}
	}()
	return results
}

func (r *ContainerImageAllLayers) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return fileMetadataByLocation(r.img, location)
}

func (r *ContainerImageAllLayers) annotateLocation(l *file.Location) {
	if !r.markVisibility || l == nil {
		return
	}

	givenRef := l.Reference()
	annotation := file.VisibleAnnotation

	// if we find a location for a path that matches the query (e.g. **/node_modules) but is not present in the squashed tree, skip it
	ref, err := r.img.SquashedSearchContext.SearchByPath(l.RealPath, filetree.DoNotFollowDeadBasenameLinks)
	if err != nil || !ref.HasReference() {
		annotation = file.HiddenAnnotation
	} else if ref.ID() != givenRef.ID() {
		// we may have the path in the squashed tree, but this must not be in the same layer
		annotation = file.HiddenAnnotation
	}

	// not only should the real path to the file exist, but the way we took to get there should also exist
	// (e.g. if we are looking for /etc/passwd, but the real path is /etc/passwd -> /etc/passwd-1, then we should
	// make certain that /etc/passwd-1 exists)
	if annotation == file.VisibleAnnotation && l.AccessPath != "" {
		ref, err := r.img.SquashedSearchContext.SearchByPath(l.AccessPath, filetree.DoNotFollowDeadBasenameLinks)
		if err != nil || !ref.HasReference() {
			annotation = file.HiddenAnnotation
		} else if ref.ID() != givenRef.ID() {
			// we may have the path in the squashed tree, but this must not be in the same layer
			annotation = file.HiddenAnnotation
		}
	}

	l.Annotations[file.VisibleAnnotationKey] = annotation
}
