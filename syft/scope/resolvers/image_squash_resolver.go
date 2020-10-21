package resolvers

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

// ImageSquashResolver implements path and content access for the Squashed scope option for container image data sources.
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
func (r *ImageSquashResolver) FilesByPath(paths ...file.Path) ([]file.Reference, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueFiles := make([]file.Reference, 0)

	for _, path := range paths {
		ref := r.img.SquashedTree().File(path)
		if ref == nil {
			// no file found, keep looking through layers
			continue
		}

		resolvedRef, err := r.img.ResolveLinkByImageSquash(*ref)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve link from img (ref=%+v): %w", ref, err)
		}
		if resolvedRef != nil && !uniqueFileIDs.Contains(*resolvedRef) {
			uniqueFileIDs.Add(*resolvedRef)
			uniqueFiles = append(uniqueFiles, *resolvedRef)
		}
	}

	return uniqueFiles, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern within the squashed representation of the image.
func (r *ImageSquashResolver) FilesByGlob(patterns ...string) ([]file.Reference, error) {
	uniqueFileIDs := file.NewFileReferenceSet()
	uniqueFiles := make([]file.Reference, 0)

	for _, pattern := range patterns {
		refs, err := r.img.SquashedTree().FilesByGlob(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve files by glob (%s): %w", pattern, err)
		}

		for _, ref := range refs {
			resolvedRefs, err := r.FilesByPath(ref.Path)
			if err != nil {
				return nil, fmt.Errorf("failed to find files by path (ref=%+v): %w", ref, err)
			}
			for _, resolvedRef := range resolvedRefs {
				if !uniqueFileIDs.Contains(resolvedRef) {
					uniqueFileIDs.Add(resolvedRef)
					uniqueFiles = append(uniqueFiles, resolvedRef)
				}
			}
		}
	}

	return uniqueFiles, nil
}

// MultipleFileContentsByRef returns the file contents for all file.References relative to the image. Note that a
// file.Reference is a path relative to a particular layer, in this case only from the squashed representation.
func (r *ImageSquashResolver) MultipleFileContentsByRef(f ...file.Reference) (map[file.Reference]string, error) {
	return r.img.MultipleFileContentsByRef(f...)
}

// FileContentsByRef fetches file contents for a single file reference, irregardless of the source layer.
// If the path does not exist an error is returned.
func (r *ImageSquashResolver) FileContentsByRef(ref file.Reference) (string, error) {
	return r.img.FileContentsByRef(ref)
}
