package fileresolver

import (
	"errors"
	"fmt"

	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/syft/file"
)

var ErrSkipPath = errors.New("skip path")

var _ file.Resolver = (*Directory)(nil)

// Directory implements path and content access for the directory data source.
type Directory struct {
	filetreeResolver
	path    string
	indexer *directoryIndexer
}

func NewFromDirectory(root string, base string, pathFilters ...PathIndexVisitor) (*Directory, error) {
	r, err := newFromDirectoryWithoutIndex(root, base, pathFilters...)
	if err != nil {
		return nil, err
	}

	return r, r.buildIndex()
}

func newFromDirectoryWithoutIndex(root string, base string, pathFilters ...PathIndexVisitor) (*Directory, error) {
	chroot, err := NewChrootContextFromCWD(root, base)
	if err != nil {
		return nil, fmt.Errorf("unable to interpret chroot context: %w", err)
	}

	cleanRoot := chroot.Root()
	cleanBase := chroot.Base()

	return &Directory{
		path: cleanRoot,
		filetreeResolver: filetreeResolver{
			chroot: *chroot,
			tree:   filetree.New(),
			index:  filetree.NewIndex(),
		},
		indexer: newDirectoryIndexer(cleanRoot, cleanBase, pathFilters...),
	}, nil
}

func (r *Directory) buildIndex() error {
	if r.indexer == nil {
		return fmt.Errorf("no directory indexer configured")
	}
	tree, index, err := r.indexer.build()
	if err != nil {
		return err
	}

	r.tree = tree
	r.index = index
	r.filetreeResolver.searchContext = filetree.NewSearchContext(tree, index)

	return nil
}

// Stringer to represent a directory path data source
func (r Directory) String() string {
	return fmt.Sprintf("dir:%s", r.path)
}
