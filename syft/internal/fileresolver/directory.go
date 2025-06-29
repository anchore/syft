package fileresolver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/archiver/v3"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

type archiveAccessPath struct {
	realPath        string
	accessPath      string
	archiveDepth    int
	archiveRealPath string
}

const (
	archiveTempPathPattern        = "syft-archivePaths-"
	archiveContentTempPathPattern = "syft-archive-contents-"
)

var ErrSkipPath = errors.New("skip path")

var _ file.Resolver = (*Directory)(nil)

// Directory implements path and content access for the directory data source.
type Directory struct {
	filetreeResolver
	path    string
	indexer *directoryIndexer
}

func NewFromDirectory(root, base string, maxArchiveRecursiveIndexDepth int, pathFilters ...PathIndexVisitor) (*Directory, func() error, error) {
	var cleanupFn = func() error { return nil }
	directory, err := newFromDirectoryWithoutIndex(root, base, pathFilters...)
	if err != nil {
		return nil, cleanupFn, err
	}

	if err = directory.buildIndex(); err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to build index: %w", err)
	}

	if maxArchiveRecursiveIndexDepth != 0 {
		archiveTempDir, err := os.MkdirTemp("", archiveTempPathPattern)
		if err != nil {
			return nil, cleanupFn, fmt.Errorf("unable to create tempdir for archive processing: %w", err)
		}

		return directory, func() error {
			return os.RemoveAll(archiveTempDir)
		}, directory.buildArchiveIndex(archiveTempDir, directory.indexer.archivePaths, maxArchiveRecursiveIndexDepth)
	}

	return directory, cleanupFn, nil
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
	r.searchContext = filetree.NewSearchContext(tree, index)

	return nil
}

func (r *Directory) buildArchiveIndex(archiveTempDir string, archives []string, maxArchiveIndexDepth int) error {
	archivesToIndex := make([]archiveAccessPath, len(archives))
	for i, archive := range archives {
		archivesToIndex[i] = archiveAccessPath{realPath: archive, accessPath: archive, archiveRealPath: archive}
	}

loop:
	for {
		var currentArchivePath archiveAccessPath
		switch len(archivesToIndex) {
		case 0:
			break loop
		case 1:
			currentArchivePath, archivesToIndex = archivesToIndex[0], nil
		default:
			currentArchivePath, archivesToIndex = archivesToIndex[0], archivesToIndex[1:]
		}

		if maxArchiveIndexDepth != -1 && currentArchivePath.archiveDepth >= maxArchiveIndexDepth {
			continue
		}

		archivePath, err := os.MkdirTemp(archiveTempDir, archiveContentTempPathPattern)
		if err != nil {
			return fmt.Errorf("unable to create tempdir for archive processing: %w", err)
		}

		archiveRealPath, err := filepath.EvalSymlinks(archivePath)
		if err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				// we can't index the path, but we shouldn't consider this to be fatal
				// TODO: known-unknowns
				log.WithFields("archivePath", archivePath, "error", err).Trace("unable to evaluate symlink while indexing branch")
				return nil
			}
			return err
		}

		envelopedUnarchiver, err := archiver.ByExtension(currentArchivePath.archiveRealPath)
		if err != nil {
			return err
		}

		unarchiver, ok := envelopedUnarchiver.(archiver.Unarchiver)
		if !ok {
			return ErrSkipPath
		}

		if err = unarchiver.Unarchive(currentArchivePath.archiveRealPath, archiveRealPath); err != nil {
			return err
		}

		d, err := newFromDirectoryWithoutIndex(archiveRealPath, "")
		if err != nil {
			return err
		}

		if err = d.buildIndex(); err != nil {
			return err
		}

		for _, archive := range d.indexer.archivePaths {
			archivesToIndex = append(archivesToIndex, archiveAccessPath{
				realPath:        currentArchivePath.realPath,
				accessPath:      strings.Replace(archive, archiveRealPath, currentArchivePath.accessPath, 1),
				archiveDepth:    currentArchivePath.archiveDepth + 1,
				archiveRealPath: archive,
			})
		}

		d.chroot = r.chroot
		d.realPath = currentArchivePath.realPath
		d.accessPath = currentArchivePath.accessPath
		d.tempDir = archiveRealPath

		r.archives = append(r.archives, &d.filetreeResolver)
	}

	return nil
}

// Stringer to represent a directory path data source
func (r Directory) String() string {
	return fmt.Sprintf("dir:%s", r.path)
}
