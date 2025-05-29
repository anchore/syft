package snapsource

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	diskFile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/afero"

	"github.com/anchore/clio"
	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/bus"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event/monitor"
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
	id               artifact.ID
	config           Config
	resolver         file.Resolver
	mutex            *sync.Mutex
	manifest         snapManifest
	digests          []file.Digest
	fs               filesystem.FileSystem
	squashfsPath     string
	squashFileCloser func() error
	closer           func() error
}

func New(cfg Config) (source.Source, error) {
	client := intFile.NewGetter(cfg.ID, cleanhttp.DefaultClient())
	f, err := getSnapFile(context.Background(), afero.NewOsFs(), client, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to open snap manifest file: %w", err)
	}

	s := &snapSource{
		id:           deriveID(cfg.Request, cfg.Alias.Name, cfg.Alias.Version),
		config:       cfg,
		mutex:        &sync.Mutex{},
		digests:      f.Digests,
		squashfsPath: f.Path,
		closer:       f.Cleanup,
	}

	return s, s.extractManifest()
}

func (s *snapSource) extractManifest() error {
	r, err := s.FileResolver(source.SquashedScope)
	if err != nil {
		return fmt.Errorf("unable to create snap file resolver: %w", err)
	}

	manifest, err := parseManifest(r)
	if err != nil {
		return fmt.Errorf("unable to parse snap manifest file: %w", err)
	}

	if manifest != nil {
		s.manifest = *manifest
	}
	return nil
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
			Digests:       s.digests,
		},
	}
}

func (s *snapSource) Close() error {
	if s.squashFileCloser != nil {
		if err := s.squashFileCloser(); err != nil {
			return fmt.Errorf("unable to close snap resolver: %w", err)
		}
		s.squashFileCloser = nil
	}
	s.resolver = nil
	if s.fs != nil {
		if err := s.fs.Close(); err != nil {
			return fmt.Errorf("unable to close snap squashfs: %w", err)
		}
	}
	if s.closer != nil {
		if err := s.closer(); err != nil {
			return fmt.Errorf("unable to close snap source: %w", err)
		}
	}
	return nil
}

func (s *snapSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		return s.resolver, nil
	}

	log.Debugf("parsing squashfs file: %s", s.squashfsPath)

	f, err := os.Open(s.squashfsPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open squashfs file: %w", err)
	}

	s.squashFileCloser = func() error {
		if err := f.Close(); err != nil {
			return fmt.Errorf("unable to close squashfs file: %w", err)
		}
		return nil
	}

	fileMeta, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("unable to stat squashfs file: %w", err)
	}

	size := fileMeta.Size()

	fileCatalog := image.NewFileCatalog()

	prog := bus.StartIndexingFiles(filepath.Base(s.squashfsPath))

	b := diskFile.New(f, true)
	fs, err := squashfs.Read(b, fileMeta.Size(), 0, 0)
	if err != nil {
		err := fmt.Errorf("unable to open squashfs file: %w", err)
		prog.SetError(err)
		return nil, err
	}

	tree := filetree.New()
	if err := intFile.WalkDiskDir(fs, "/", squashfsVisitor(tree, fileCatalog, &size, prog)); err != nil {
		err := fmt.Errorf("failed to walk squashfs file=%q: %w", s.squashfsPath, err)
		prog.SetError(err)
		return nil, err
	}

	prog.SetCompleted()

	s.resolver = &fileresolver.FiletreeResolver{
		Chroot:        fileresolver.ChrootContext{},
		Tree:          tree,
		Index:         fileCatalog.Index,
		SearchContext: filetree.NewSearchContext(tree, fileCatalog.Index),
		Opener: func(ref stereoFile.Reference) (io.ReadCloser, error) {
			return fileCatalog.Open(ref)
		},
	}

	s.fs = fs

	return s.resolver, nil
}

type linker interface {
	Readlink() (string, error)
}

func squashfsVisitor(ft filetree.Writer, fileCatalog *image.FileCatalog, size *int64, prog *monitor.TaskProgress) intFile.WalkDiskDirFunc {
	builder := filetree.NewBuilder(ft, fileCatalog.Index)

	return func(fsys filesystem.FileSystem, path string, d os.FileInfo, walkErr error) error {
		if walkErr != nil {
			log.WithFields("error", walkErr, "path", path).Trace("unable to walk squash file path")
			return walkErr
		}

		prog.AtomicStage.Set(path)

		var f filesystem.File
		var mimeType string
		var err error

		if !d.IsDir() {
			f, err = fsys.OpenFile(path, os.O_RDONLY)
			if err != nil {
				log.WithFields("error", err, "path", path).Trace("unable to open squash file path")
			} else {
				defer f.Close()
				mimeType = stereoFile.MIMEType(f)
			}
		}

		var ty stereoFile.Type
		var linkPath string
		switch {
		case d.IsDir():
			// in some implementations, the mode does not indicate a directory, so we check the FileInfo type explicitly
			ty = stereoFile.TypeDirectory
		default:
			ty = stereoFile.TypeFromMode(d.Mode())
			if ty == stereoFile.TypeSymLink && f != nil {
				if l, ok := f.(linker); ok {
					linkPath, _ = l.Readlink()
				}
			}
		}

		metadata := stereoFile.Metadata{
			FileInfo:        d,
			Path:            path,
			LinkDestination: linkPath,
			Type:            ty,
			MIMEType:        mimeType,
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
		fileCatalog.AssociateOpener(*fileReference, func() (io.ReadCloser, error) {
			return fsys.OpenFile(path, os.O_RDONLY)
		})

		prog.Increment()
		return nil
	}
}

func isSquashFSFile(mimeType, path string) bool {
	if mimeType == "application/vnd.squashfs" || mimeType == "application/x-squashfs" {
		return true
	}

	ext := filepath.Ext(path)
	return ext == ".snap" || ext == ".squashfs"
}

func deriveID(path, name, version string) artifact.ID {
	info := fmt.Sprintf("%s:%s@%s", digestOfFileContents(path), name, version)
	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(info).String())
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
