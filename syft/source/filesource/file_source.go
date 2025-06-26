package filesource

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/opencontainers/go-digest"

	stereoFile "github.com/anchore/stereoscope/pkg/file"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/internal"
	"github.com/mholt/archives"
)

var _ source.Source = (*fileSource)(nil)

type Config struct {
	Path               string
	Exclude            source.ExcludeConfig
	DigestAlgorithms   []crypto.Hash
	Alias              source.Alias
	SkipExtractArchive bool
}

type fileSource struct {
	id               artifact.ID
	digestForVersion string
	config           Config
	resolver         file.Resolver
	mutex            *sync.Mutex
	closer           func() error
	digests          []file.Digest
	mimeType         string
	analysisPath     string
}

func NewFromPath(path string) (source.Source, error) {
	return New(Config{Path: path})
}

func New(cfg Config) (source.Source, error) {
	fileMeta, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", cfg.Path, err)
	}

	if fileMeta.IsDir() {
		return nil, fmt.Errorf("given path is a directory: %q", cfg.Path)
	}

	analysisPath, cleanupFn, err := fileAnalysisPath(cfg.Path, cfg.SkipExtractArchive)
	if err != nil {
		return nil, fmt.Errorf("unable to extract file analysis path=%q: %w", cfg.Path, err)
	}

	var digests []file.Digest
	if len(cfg.DigestAlgorithms) > 0 {
		fh, err := os.Open(cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("unable to open file=%q: %w", cfg.Path, err)
		}

		defer fh.Close()

		digests, err = intFile.NewDigestsFromFile(context.TODO(), fh, cfg.DigestAlgorithms)
		if err != nil {
			return nil, fmt.Errorf("unable to calculate digests for file=%q: %w", cfg.Path, err)
		}
	}

	fh, err := os.Open(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file=%q: %w", cfg.Path, err)
	}

	defer fh.Close()

	id, versionDigest := deriveIDFromFile(cfg)

	return &fileSource{
		id:               id,
		config:           cfg,
		mutex:            &sync.Mutex{},
		closer:           cleanupFn,
		analysisPath:     analysisPath,
		digestForVersion: versionDigest,
		digests:          digests,
		mimeType:         stereoFile.MIMEType(fh),
	}, nil
}

// deriveIDFromFile derives an artifact ID from the contents of a file. If an alias is provided, it will be included
// in the ID derivation (along with contents). This way if the user scans the same item but is considered to be
// logically different, then ID will express that.
func deriveIDFromFile(cfg Config) (artifact.ID, string) {
	d := digestOfFileContents(cfg.Path)
	info := d

	if !cfg.Alias.IsEmpty() {
		// if the user provided an alias, we want to consider that in the artifact ID. This way if the user
		// scans the same item but is considered to be logically different, then ID will express that.
		info += fmt.Sprintf(":%s@%s", cfg.Alias.Name, cfg.Alias.Version)
	}

	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(info).String()), d
}

func (s fileSource) ID() artifact.ID {
	return s.id
}

func (s fileSource) Describe() source.Description {
	name := path.Base(s.config.Path)
	version := s.digestForVersion
	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}

		if a.Version != "" {
			version = a.Version
		}
	}
	return source.Description{
		ID:      string(s.id),
		Name:    name,
		Version: version,
		Metadata: source.FileMetadata{
			Path:     s.config.Path,
			Digests:  s.digests,
			MIMEType: s.mimeType,
		},
	}
}

func (s fileSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		return s.resolver, nil
	}

	exclusionFunctions, err := directorysource.GetDirectoryExclusionFunctions(s.analysisPath, s.config.Exclude.Paths)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(s.analysisPath)
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", s.analysisPath, err)
	}
	isArchiveAnalysis := fi.IsDir()

	absParentDir, err := absoluteSymlinkFreePathToParent(s.analysisPath)
	if err != nil {
		return nil, err
	}

	if isArchiveAnalysis {
		// this is an analysis of an archive file... we should scan the directory where the archive contents
		res, err := fileresolver.NewFromDirectory(s.analysisPath, "", exclusionFunctions...)
		if err != nil {
			return nil, fmt.Errorf("unable to create directory resolver: %w", err)
		}
		s.resolver = res
		return s.resolver, nil
	}

	// This is analysis of a single file. Use file indexer.
	res, err := fileresolver.NewFromFile(absParentDir, s.analysisPath, exclusionFunctions...)
	if err != nil {
		return nil, fmt.Errorf("unable to create file resolver: %w", err)
	}
	s.resolver = res
	return s.resolver, nil
}

func absoluteSymlinkFreePathToParent(path string) (string, error) {
	absAnalysisPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("unable to get absolute path for analysis path=%q: %w", path, err)
	}
	dereferencedAbsAnalysisPath, err := filepath.EvalSymlinks(absAnalysisPath)
	if err != nil {
		return "", fmt.Errorf("unable to get absolute path for analysis path=%q: %w", path, err)
	}
	return filepath.Dir(dereferencedAbsAnalysisPath), nil
}

func (s *fileSource) Close() error {
	if s.closer == nil {
		return nil
	}
	s.resolver = nil
	return s.closer()
}

// fileAnalysisPath returns the path given, or in the case the path is an archive, the location where the archive
// contents have been made available. A cleanup function is provided for any temp files created (if any).
// Users can disable unpacking archives, allowing individual cataloguers to extract them instead (where
// supported)
func fileAnalysisPath(path string, skipExtractArchive bool) (string, func() error, error) {
	var cleanupFn = func() error { return nil }
	var analysisPath = path

	if skipExtractArchive {
		return analysisPath, cleanupFn, nil
	}

	// if the given file is an archive (as indicated by the file extension and not MIME type) then unarchive it and
	// use the contents as the source. Note: this does NOT recursively unarchive contents, only the given path is
	// unarchived.
	envelopedUnarchiver, _, err := archives.Identify(context.Background(), path, nil)
	if unarchiver, ok := envelopedUnarchiver.(archives.Extractor); err == nil && ok {
		analysisPath, cleanupFn, err = unarchiveToTmp(path, unarchiver)
		if err != nil {
			return "", nil, fmt.Errorf("unable to unarchive source file: %w", err)
		}

		log.Debugf("source path is an archive")
	}

	return analysisPath, cleanupFn, nil
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

func unarchiveToTmp(path string, unarchiver archives.Extractor) (string, func() error, error) {
	archive, err := os.Open(path)
	if err != nil {
		fmt.Errorf("unable to open archive: %v", err)
	}
	defer archive.Close()

	tempDir, err := os.MkdirTemp("", "syft-archive-contents-")
	if err != nil {
		return "", func() error { return nil }, fmt.Errorf("unable to create tempdir for archive processing: %w", err)
	}

	visitor := func(ctx context.Context, file archives.FileInfo) error {
		destPath := filepath.Join(tempDir, file.NameInArchive)
		if file.IsDir() {
			return os.MkdirAll(destPath, file.Mode())
		}

		if err := os.MkdirAll(filepath.Dir(destPath), os.ModeDir|0755); err != nil {
			return fmt.Errorf("failed to create parent directory: %w", err)
		}

		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in archive: %w", err)
		}
		defer rc.Close()

		destFile, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("failed to create file in destination: %w", err)
		}
		defer destFile.Close()

		if err := destFile.Chmod(file.Mode()); err != nil {
			return fmt.Errorf("failed to change mode of destination file: %w", err)
		}

		if _, err := io.Copy(destFile, rc); err != nil {
			return fmt.Errorf("failed to copy file contents: %w", err)
		}

		return nil
	}

	return tempDir, func() error {
		return os.RemoveAll(tempDir)
	}, unarchiver.Extract(context.Background(), archive, visitor)
}
