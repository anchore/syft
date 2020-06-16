package resolvers

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type ImageSquashResolver struct {
	img *image.Image
}

func NewImageSquashResolver(img *image.Image) (*ImageSquashResolver, error) {
	if img.SquashedTree() == nil {
		return nil, fmt.Errorf("the image does not have have a squashed tree")
	}
	return &ImageSquashResolver{img: img}, nil
}

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
