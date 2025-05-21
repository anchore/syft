package fileresolver

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/syft/file"
)

// Compile time assurance that we meet the Resolver interface.
var _ file.Resolver = (*File)(nil)

// File implements path and content access for the file data source.
type File struct {
	FiletreeResolver
	path    string
	indexer *fileIndexer
}

// parent should be the symlink free absolute path to the parent directory
// path is the filepath of the file we're creating content access for
func NewFromFile(parent, path string, pathFilters ...PathIndexVisitor) (*File, error) {
	chroot, err := NewChrootContextFromCWD(parent, parent)
	if err != nil {
		return nil, fmt.Errorf("unable to interpret chroot context: %w", err)
	}

	cleanBase := chroot.Base()

	file := &File{
		path: path,
		FiletreeResolver: FiletreeResolver{
			Chroot: *chroot,
			Tree:   filetree.New(),
			Index:  filetree.NewIndex(),
			Opener: nativeOSFileOpener,
		},
		indexer: newFileIndexer(path, cleanBase, pathFilters...),
	}

	return file, file.buildIndex()
}

func (r *File) buildIndex() error {
	if r.indexer == nil {
		return fmt.Errorf("no file indexer configured")
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

// Stringer to represent a file path data source
func (r File) String() string {
	return fmt.Sprintf("file:%s", r.path)
}
