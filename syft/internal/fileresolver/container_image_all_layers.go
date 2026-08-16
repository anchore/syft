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

func (r *ContainerImageAllLayers) locationsByRef(ref stereoscopeFile.Reference, accessPath string, uniqueFileIDs stereoscopeFile.ReferenceSet, layerPos int) ([]file.Location, error) {
	uniqueLocations := make([]file.Location, 0)

	// if the access path is itself a hardlink, surface it as the underlying type it points to, at its own path
	// (bound to the target's content), so that image results are in parity with directory results (which cannot
	// tell a hardlink from a regular file). the path-based lookup is required because the search that produced ref
	// already followed the basename link, collapsing the hardlink onto its target.
	if ownRef, targetRef, ok := r.hardLinkAtPath(accessPath, r.layers[layerPos]); ok {
		if !uniqueFileIDs.Contains(ownRef) {
			uniqueFileIDs.Add(ownRef)
			uniqueLocations = append(uniqueLocations, file.NewVirtualLocationFromImage(string(ownRef.RealPath), accessPath, targetRef, r.img))
		}
		return uniqueLocations, nil
	}

	// since there is potentially considerable work for each symlink/hardlink that needs to be resolved, let's check to see if this is a symlink/hardlink first
	entry, err := r.img.FileCatalog.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch metadata (ref=%+v): %w", ref, err)
	}

	if entry.Type == stereoscopeFile.TypeHardLink || entry.Type == stereoscopeFile.TypeSymLink {
		// a link may resolve in this layer or higher, assuming a squashed tree is used to search
		// we should search all possible resolutions within the valid source
		for _, subLayerIdx := range r.layers[layerPos:] {
			resolvedRef, err := r.img.ResolveLinkByLayerSquash(ref, subLayerIdx)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve link from layer (layer=%d ref=%+v): %w", subLayerIdx, ref, err)
			}
			if resolvedRef.HasReference() && !uniqueFileIDs.Contains(*resolvedRef.Reference) {
				uniqueFileIDs.Add(*resolvedRef.Reference)
				uniqueLocations = append(uniqueLocations, file.NewLocationFromImage(accessPath, *resolvedRef.Reference, r.img))
			}
		}
	} else if !uniqueFileIDs.Contains(ref) {
		uniqueFileIDs.Add(ref)
		uniqueLocations = append(uniqueLocations, file.NewLocationFromImage(accessPath, ref, r.img))
	}

	return uniqueLocations, nil
}

// hardLinkAtPath returns the hardlink's own reference and its resolved target reference when the basename of path is a
// hardlink within the given layer. ok is false when path does not exist there or is not a hardlink. The lookup does
// not follow the basename link so that the hardlink's own path is preserved. This adds a tree walk per
// matched ref (path x layer); if it shows up in profiles, fold the hardlink check into the existing search resolution.
func (r *ContainerImageAllLayers) hardLinkAtPath(path string, layerIdx int) (stereoscopeFile.Reference, stereoscopeFile.Reference, bool) {
	var own stereoscopeFile.Reference
	// use the squashed-to-layer view (not just this layer's additions) so a hardlink added in a lower layer is still
	// detected when the path is searched at a higher layer; otherwise it would collapse onto its target there.
	exists, resolution, err := r.img.Layers[layerIdx].SquashedTree.File(stereoscopeFile.Path(path))
	if err != nil || !exists || !resolution.HasReference() {
		return own, own, false
	}
	target, ok := r.resolveHardLinkTarget(*resolution.Reference, layerIdx)
	if !ok {
		return own, own, false
	}
	return *resolution.Reference, target, true
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

			locations, err := r.locationsByRef(*ref.Reference, path, uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			for i := range locations {
				r.annotateLocation(&locations[i])
				uniqueLocations = append(uniqueLocations, locations[i])
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

				locations, err := r.locationsByRef(*result.Reference, string(result.RequestPath), uniqueFileIDs, idx)
				if err != nil {
					return nil, err
				}
				for i := range locations {
					r.annotateLocation(&locations[i])
					uniqueLocations = append(uniqueLocations, locations[i])
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

			locations, err := r.locationsByRef(*ref.Reference, string(ref.RequestPath), uniqueFileIDs, idx)
			if err != nil {
				return nil, err
			}
			for i := range locations {
				r.annotateLocation(&locations[i])
				uniqueLocations = append(uniqueLocations, locations[i])
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
				// surface a hardlink as the underlying type it points to (at its own path) so image results match
				// directory results, which cannot distinguish a hardlink from a regular file.
				if targetRef, ok := r.resolveHardLinkTarget(ref, layerIdx); ok {
					l = file.NewVirtualLocationFromImage(string(ref.RealPath), string(ref.RealPath), targetRef, r.img)
				}
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

// resolveHardLinkTarget returns the reference of a hardlink's underlying target (resolved relative to the given layer)
// when ref is a hardlink; ok is false otherwise. No resolution is performed for non-hardlinks (symlinks keep their
// existing resolution semantics).
func (r *ContainerImageAllLayers) resolveHardLinkTarget(ref stereoscopeFile.Reference, layerIdx int) (stereoscopeFile.Reference, bool) {
	metadata, err := r.img.FileCatalog.Get(ref)
	if err != nil || metadata.Type != stereoscopeFile.TypeHardLink {
		return ref, false
	}
	resolved, err := r.img.ResolveLinkByLayerSquash(ref, layerIdx)
	if err != nil || !resolved.HasReference() {
		return ref, false
	}
	return *resolved.Reference, true
}

func (r *ContainerImageAllLayers) annotateLocation(l *file.Location) {
	if !r.markVisibility || l == nil {
		return
	}

	givenRef := l.Reference()
	annotation := file.VisibleAnnotation

	// if we find a location for a path that matches the query (e.g. **/node_modules) but is not present in the squashed tree, skip it
	if !r.pathResolvesToRef(l.RealPath, givenRef) {
		annotation = file.HiddenAnnotation
	}

	// not only should the real path to the file exist, but the way we took to get there should also exist
	// (e.g. if we are looking for /etc/passwd, but the real path is /etc/passwd -> /etc/passwd-1, then we should
	// make certain that /etc/passwd-1 exists)
	if annotation == file.VisibleAnnotation && l.AccessPath != "" && !r.pathResolvesToRef(l.AccessPath, givenRef) {
		annotation = file.HiddenAnnotation
	}

	l.Annotations[file.VisibleAnnotationKey] = annotation
}

// pathResolvesToRef reports whether the given path in the squashed tree resolves to the given reference.
// SearchByPath always follows basename links, so a hardlink surfaced at its own path (whose reference is its
// target) still resolves to the target here and is correctly considered visible.
func (r *ContainerImageAllLayers) pathResolvesToRef(path string, target stereoscopeFile.Reference) bool {
	ref, err := r.img.SquashedSearchContext.SearchByPath(path, filetree.DoNotFollowDeadBasenameLinks)
	return err == nil && ref.HasReference() && ref.ID() == target.ID()
}
