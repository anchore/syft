package snapsource

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/afero"
	"github.com/sylabs/squashfs"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*snapSource)(nil)

type Config struct {
	ID clio.Identification

	Request          string
	Platform         *image.Platform
	Exclude          source.ExcludeConfig
	DigestAlgorithms []crypto.Hash
	Alias            source.Alias
}

type snapSource struct {
	id           artifact.ID
	config       Config
	resolver     file.Resolver
	mutex        *sync.Mutex
	squashfsPath string
	manifest     *snapManifest
	closer       func() error
}

func New(cfg Config) (source.Source, error) {
	client := intFile.NewGetter(cfg.ID, cleanhttp.DefaultClient())
	f, err := getSnapFile(context.Background(), afero.NewOsFs(), client, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to open snap manifest file: %w", err)
	}

	s := &snapSource{
		config:       cfg,
		mutex:        &sync.Mutex{},
		squashfsPath: f.Path,
		closer:       f.Cleanup,
	}

	s.id = s.deriveID(cfg.Request, s.config.Alias.Name, s.config.Alias.Version)

	r, err := s.FileResolver(source.SquashedScope)
	if err != nil {
		return nil, fmt.Errorf("unable to create snap file resolver: %w", err)
	}

	manifest, err := parseManifest(r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse snap manifest file: %w", err)
	}

	s.manifest = manifest

	return s, nil
}

func isSquashFSFile(mimeType, path string) bool {
	if mimeType == "application/vnd.squashfs" || mimeType == "application/x-squashfs" {
		return true
	}

	ext := filepath.Ext(path)
	return ext == ".snap" || ext == ".squashfs"
}

func (s snapSource) deriveID(path, name, version string) artifact.ID {
	info := fmt.Sprintf("%s:%s@%s", digestOfFileContents(path), name, version)
	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(info).String())
}

func (s snapSource) ID() artifact.ID {
	return s.id
}

func (s snapSource) NameVersion() (string, string) {
	name := s.manifest.Name
	version := s.manifest.Version
	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}

		if a.Version != "" {
			version = a.Version
		}
	}
	return name, version
}

func (s snapSource) Describe() source.Description {
	name, version := s.NameVersion()
	return source.Description{
		ID:      string(s.id),
		Name:    name,
		Version: version,
		Metadata: source.SnapMetadata{
			Summary:       s.manifest.Summary,
			Base:          s.manifest.Base,
			Grade:         s.manifest.Grade,
			Confinement:   s.manifest.Confinement,
			Architectures: s.manifest.Architectures,
		},
	}
}

func (s *snapSource) Close() error {
	s.resolver = nil
	if s.closer != nil {
		if err := s.closer(); err != nil {
			return fmt.Errorf("unable to close snap source: %w", err)
		}
	}
	return nil
}

func (s snapSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		return s.resolver, nil
	}

	log.Debugf("parsing squashfs file: %s", s.squashfsPath)

	var size int64
	fileMeta, err := os.Stat(s.squashfsPath)
	if err == nil {
		size = fileMeta.Size()
	}

	fileCatalog := image.NewFileCatalog()

	// TODO: publish this on the bus
	monitor := progress.NewManual(-1)

	tree := filetree.New()
	if err := stereoFile.WalkSquashFS(s.squashfsPath, squashfsVisitor(tree, fileCatalog, &size, monitor)); err != nil {
		return nil, fmt.Errorf("failed to walk squashfs file=%q: %w", s.squashfsPath, err)
	}

	monitor.SetCompleted()

	s.resolver = &fileresolver.FiletreeResolver{
		Chroot:        fileresolver.ChrootContext{},
		Tree:          tree,
		Index:         fileCatalog.Index,
		SearchContext: filetree.NewSearchContext(tree, fileCatalog.Index),
		Opener: func(ref stereoFile.Reference) (io.ReadCloser, error) {
			return fileCatalog.Open(ref)
		},
	}

	return s.resolver, nil
}

func squashfsVisitor(ft filetree.Writer, fileCatalog *image.FileCatalog, size *int64, monitor *progress.Manual) stereoFile.SquashFSVisitor {
	builder := filetree.NewBuilder(ft, fileCatalog.Index)

	return func(fsys fs.FS, sqfsPath, path string) error {
		ff, err := fsys.Open(path)
		if err != nil {
			return err
		}
		defer ff.Close()

		f, ok := ff.(*squashfs.File)
		if !ok {
			return errors.New("unexpected file type from squashfs")
		}

		metadata, err := stereoFile.NewMetadataFromSquashFSFile(path, f)
		if err != nil {
			return err
		}

		fileReference, err := builder.Add(metadata)
		if err != nil {
			return err
		}

		if fileReference == nil {
			return nil
		}

		if size != nil {
			*(size) += metadata.Size()
		}
		fileCatalog.Add(*fileReference, metadata, nil, func() (io.ReadCloser, error) {
			return newSquashfsFileReader(sqfsPath, path)
		})

		monitor.Increment()
		return nil
	}
}

// squashfsReader implements an io.ReadCloser that reads a file from within a SquashFS filesystem.
type squashfsReader struct {
	fs.File
	backingFile *os.File
}

// newSquashfsFileReader returns a io.ReadCloser that reads the file at path within the SquashFS
// filesystem at sqfsPath.
func newSquashfsFileReader(sqfsPath, path string) (io.ReadCloser, error) {
	f, err := os.Open(sqfsPath)
	if err != nil {
		return nil, err
	}

	fsys, err := squashfs.NewReader(f)
	if err != nil {
		return nil, err
	}

	r, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}

	return &squashfsReader{
		File:        r,
		backingFile: f,
	}, nil
}

// Close closes the SquashFS file as well as the backing filesystem.
func (f *squashfsReader) Close() error {
	if err := f.File.Close(); err != nil {
		return err
	}

	return f.backingFile.Close()
}

func digestOfFileContents(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return digest.SHA256.FromString(path).String()
	}
	defer file.Close()
	di, err := digest.SHA256.FromReader(file)
	if err != nil {
		return digest.SHA256.FromString(path).String()
	}
	return di.String()
}
