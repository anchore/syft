package appimagesource

import (
	"context"
	"crypto"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OneOfOne/xxhash"
	diskFile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/afero"

	"github.com/anchore/clio"
	"github.com/anchore/go-homedir"
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

var _ source.Source = (*appImageSource)(nil)

type Config struct {
	ID clio.Identification

	Request          string
	Platform         *image.Platform
	Exclude          source.ExcludeConfig
	DigestAlgorithms []crypto.Hash
	Alias            source.Alias

	fs afero.Fs
}

type appImageSource struct {
	id                 artifact.ID
	config             Config
	resolver           file.Resolver
	mutex              *sync.Mutex
	digests            []file.Digest
	fs                 filesystem.FileSystem
	appImagePath       string
	payloadOffset      int64
	appImageFileCloser func() error
	closer             func() error
	metadata           source.AppImageMetadata
}

func NewFromPath(cfg Config) (source.Source, error) {
	expandedPath, err := homedir.Expand(cfg.Request)
	if err != nil {
		return nil, fmt.Errorf("unable to expand path %q: %w", cfg.Request, err)
	}
	cfg.Request = filepath.Clean(expandedPath)

	if cfg.fs == nil {
		cfg.fs = afero.NewOsFs()
	}

	if !fileExists(cfg.fs, cfg.Request) {
		return nil, fmt.Errorf("appimage file %q does not exist", cfg.Request)
	}

	f, err := os.Open(cfg.Request)
	if err != nil {
		return nil, fmt.Errorf("unable to open appimage file %q: %w", cfg.Request, err)
	}
	defer f.Close()

	if !isAppImageFile(f) {
		return nil, nil // Not an AppImage, let other providers try
	}

	offset, err := findSquashFSOffset(f)
	if err != nil {
		return nil, fmt.Errorf("unable to find SquashFS offset in AppImage %q: %w", cfg.Request, err)
	}

	var digests []file.Digest
	if len(cfg.DigestAlgorithms) > 0 {
		digests, err = intFile.NewDigestsFromFile(context.TODO(), f, cfg.DigestAlgorithms)
		if err != nil {
			return nil, fmt.Errorf("unable to calculate digests for appimage %q: %w", cfg.Request, err)
		}
	}

	s := &appImageSource{
		config:        cfg,
		mutex:         &sync.Mutex{},
		digests:       digests,
		appImagePath:  cfg.Request,
		payloadOffset: offset,
	}

	if err := s.discoverMetadata(); err != nil {
		log.Warnf("unable to discover metadata for appimage %q: %v", cfg.Request, err)
	}

	s.id = deriveID(cfg.Request, s.metadata.Name, s.metadata.Version, digests)

	return s, nil
}

func (s appImageSource) ID() artifact.ID {
	return s.id
}

func (s appImageSource) NameVersion() (string, string) {
	name := s.metadata.Name
	if name == "" {
		name = filepath.Base(s.appImagePath)
	}
	version := s.metadata.Version
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

func (s appImageSource) Describe() source.Description {
	name, version := s.NameVersion()
	return source.Description{
		ID:       string(s.id),
		Name:     name,
		Version:  version,
		Metadata: s.metadata,
	}
}

type readerAtSeekerCloser struct {
	*io.SectionReader
}

func (r readerAtSeekerCloser) Close() error                { return nil }
func (r readerAtSeekerCloser) Write(_ []byte) (int, error) { return 0, fmt.Errorf("read-only") }
func (r readerAtSeekerCloser) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("read-only")
}

func (r readerAtSeekerCloser) Stat() (os.FileInfo, error) {
	return fakeFileInfo{size: r.SectionReader.Size()}, nil
}

type fakeFileInfo struct {
	size int64
}

func (f fakeFileInfo) Name() string       { return "appimage-payload" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0444 }
func (f fakeFileInfo) ModTime() time.Time { return time.Now() }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() interface{}   { return nil }

func (s *appImageSource) discoverMetadata() error {
	res, err := s.FileResolver(source.SquashedScope)
	if err != nil {
		return err
	}

	// look for .desktop file
	var desktopLoc *file.Location
	files, err := res.FilesByGlob("/**/*.desktop")
	log.Debugf("discovered %d .desktop files in appimage", len(files))
	if err == nil && len(files) > 0 {
		// Prefer the one that is closest to the root or has the shortest path
		best := files[0]
		for _, f := range files {
			if len(string(f.RealPath)) < len(string(best.RealPath)) {
				best = f
			}
		}
		desktopLoc = &best
		log.Debugf("using .desktop file: %s", best.RealPath)
	}

	if desktopLoc == nil {
		return nil
	}

	s.metadata.DesktopPath = string(desktopLoc.RealPath)
	s.metadata.Digests = s.digests

	reader, err := res.FileContentsByLocation(*desktopLoc)
	if err != nil {
		return err
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// simple .desktop parser
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name=") && s.metadata.Name == "" {
			s.metadata.Name = strings.TrimPrefix(line, "Name=")
		}
		if strings.HasPrefix(line, "X-AppImage-Version=") {
			s.metadata.Version = strings.TrimPrefix(line, "X-AppImage-Version=")
		}
	}

	return nil
}

func (s *appImageSource) Close() error {
	if s.appImageFileCloser != nil {
		if err := s.appImageFileCloser(); err != nil {
			return fmt.Errorf("unable to close appimage resolver: %w", err)
		}
		s.appImageFileCloser = nil
	}
	s.resolver = nil
	if s.fs != nil {
		// diskfs doesn't have a Close on the filesystem itself usually, but let's check
	}
	if s.closer != nil {
		if err := s.closer(); err != nil {
			return fmt.Errorf("unable to close appimage source: %w", err)
		}
	}
	return nil
}

func (s *appImageSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		return s.resolver, nil
	}

	f, err := os.Open(s.appImagePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open appimage file: %w", err)
	}

	s.appImageFileCloser = func() error {
		if err := f.Close(); err != nil {
			return fmt.Errorf("unable to close appimage file: %w", err)
		}
		return nil
	}

	fileMeta, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("unable to stat appimage file: %w", err)
	}

	log.Debugf("parsing appimage payload at offset %d: %s (file size: %d)", s.payloadOffset, s.appImagePath, fileMeta.Size())

	size := fileMeta.Size() - s.payloadOffset
	log.Debugf("creating SectionReader at offset %d with size %d (total file size %d)", s.payloadOffset, size, fileMeta.Size())

	fileCatalog := image.NewFileCatalog()

	name := filepath.Base(s.appImagePath)
	if s.metadata.Name != "" {
		name = s.metadata.Name
		if s.metadata.Version != "" {
			name = fmt.Sprintf("%s %s", name, s.metadata.Version)
		}
	}
	prog := bus.StartIndexingFiles(name)

	sr := io.NewSectionReader(f, s.payloadOffset, size)
	log.Debugf("SectionReader created, size: %d", sr.Size())
	b := diskFile.New(&readerAtSeekerCloser{sr}, true)
	fs, err := squashfs.Read(b, size, 0, 0)
	if err != nil {
		err := fmt.Errorf("unable to open squashfs payload in appimage: %w", err)
		prog.SetError(err)
		return nil, err
	}

	tree := filetree.New()
	if err := intFile.WalkDiskDir(fs, "/", squashfsVisitor(tree, fileCatalog, &size, prog)); err != nil {
		err := fmt.Errorf("failed to walk squashfs payload in appimage=%q: %w", s.appImagePath, err)
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
			ty = stereoFile.TypeDirectory
		default:
			ty = stereoFile.TypeFromMode(d.Mode())
			if ty == stereoFile.TypeSymLink && f != nil {
				if l, ok := f.(interface{ Readlink() (string, error) }); ok {
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

func isAppImageFile(r io.ReaderAt) bool {
	magic := make([]byte, 3)
	_, err := r.ReadAt(magic, 8)
	if err != nil {
		return false
	}
	return string(magic) == "AI\x02"
}

func findSquashFSOffset(r io.ReaderAt) (int64, error) {
	f, err := elf.NewFile(io.NewSectionReader(r, 0, 1<<62))
	if err != nil {
		return 0, fmt.Errorf("failed to parse ELF: %w", err)
	}

	var maxOffset uint64
	for _, prog := range f.Progs {
		end := prog.Off + prog.Filesz
		if end > maxOffset {
			maxOffset = end
		}
	}
	for _, sect := range f.Sections {
		end := sect.Offset + sect.Size
		if end > maxOffset {
			maxOffset = end
		}
	}

	// ELF section header table might be at the end
	// Note: debug/elf doesn't expose Shoff directly in FileHeader,
	// but it uses it internally. We can assume maxOffset covers it if we use sections.
	// Actually, let's be careful. The section header table itself is not a section.
	// We might need to read the ELF header manually if we want to be 100% sure.

	// Check for SquashFS magic at this offset
	magic := make([]byte, 4)
	_, err = r.ReadAt(magic, int64(maxOffset))
	if err == nil && string(magic) == "hsqs" {
		return int64(maxOffset), nil
	}

	// If not exactly at maxOffset, look slightly ahead (AppImage runtime sometimes pads)
	// Or search for 'hsqs' starting from maxOffset
	searchLimit := maxOffset + 4096
	for i := maxOffset; i < searchLimit; i++ {
		_, err = r.ReadAt(magic, int64(i))
		if err != nil {
			break
		}
		if string(magic) == "hsqs" {
			return int64(i), nil
		}
	}

	return 0, fmt.Errorf("could not find SquashFS magic 'hsqs' after ELF payload")
}

func deriveID(path, name, version string, digests []file.Digest) artifact.ID {
	var xxhDigest string
	for _, d := range digests {
		if strings.ToLower(strings.ReplaceAll(d.Algorithm, "-", "")) == "xxh64" {
			xxhDigest = d.Value
			break
		}
	}

	if xxhDigest == "" {
		xxhDigest = digestOfFileContents(path)
	}

	info := fmt.Sprintf("%s:%s@%s", xxhDigest, name, version)
	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(info).String())
}

func digestOfFileContents(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return digestOfReader(strings.NewReader(path))
	}
	defer f.Close()
	return digestOfReader(f)
}

func digestOfReader(r io.Reader) string {
	hasher := xxhash.New64()
	_, _ = io.Copy(hasher, r)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func fileExists(fs afero.Fs, path string) bool {
	if fs == nil {
		fs = afero.NewOsFs()
	}
	info, err := fs.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
