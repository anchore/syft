package fileresolver

import (
	"errors"
	"fmt"

	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/syft/file"
)

var ErrSkipPath = errors.New("skip path")

var _ file.Resolver = (*DirectoryResolver)(nil)

// DirectoryResolver implements path and content access for the directory data source.
type DirectoryResolver struct {
	FiletreeResolver
	path    string
	indexer *directoryIndexer
}

func NewFromDirectory(root, base string, pathFilters ...PathIndexVisitor) (*DirectoryResolver, error) {
	r, err := newFromDirectoryWithoutIndex(root, base, pathFilters...)
	if err != nil {
		return nil, err
	}

	return r, r.buildIndex()
}

func newFromDirectoryWithoutIndex(root, base string, pathFilters ...PathIndexVisitor) (*DirectoryResolver, error) {
	chroot, err := NewChrootContextFromCWD(root, base)
	if err != nil {
		return nil, fmt.Errorf("unable to interpret chroot context: %w", err)
	}

	cleanRoot := chroot.Root()
	cleanBase := chroot.Base()

	return &DirectoryResolver{
		path: cleanRoot,
		FiletreeResolver: FiletreeResolver{
			Chroot: *chroot,
			Tree:   filetree.New(),
			Index:  filetree.NewIndex(),
			Opener: nativeOSFileOpener,
		},
		indexer: newDirectoryIndexer(cleanRoot, cleanBase, pathFilters...),
	}, nil
}

func (r *DirectoryResolver) buildIndex() error {
	if r.indexer == nil {
		return fmt.Errorf("no directory indexer configured")
	}
	tree, index, err := r.indexer.build()
	if err != nil {
		return err
	}

	r.Tree = tree
	r.Index = index
	r.SearchContext = filetree.NewSearchContext(tree, index)

	return nil
}

// Stringer to represent a directory path data source
func (r *DirectoryResolver) String() string {
	return fmt.Sprintf("dir:%s", r.path)
}
