package filesource

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"

	stereoFile "github.com/anchore/stereoscope/pkg/file"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
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
	f, err := os.Open(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file=%q: %w", cfg.Path, err)
	}
	defer f.Close()

	fileMeta, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", cfg.Path, err)
	}

	if fileMeta.IsDir() {
		return nil, fmt.Errorf("given path is a directory: %q", cfg.Path)
	}

	var digests []file.Digest
	if len(cfg.DigestAlgorithms) > 0 {
		digests, err = intFile.NewDigestsFromFile(context.TODO(), f, cfg.DigestAlgorithms)
		if err != nil {
			return nil, fmt.Errorf("unable to calculate digests for file=%q: %w", cfg.Path, err)
		}
	}

	analysisPath, cleanupFn, err := fileAnalysisPath(cfg.Path, cfg.SkipExtractArchive)
	if err != nil {
		return nil, fmt.Errorf("unable to extract file analysis path=%q: %w", cfg.Path, err)
	}

	id, versionDigest := deriveIDFromFile(cfg)

	return &fileSource{
		id:               id,
		config:           cfg,
		mutex:            &sync.Mutex{},
		closer:           cleanupFn,
		analysisPath:     analysisPath,
		digestForVersion: versionDigest,
		digests:          digests,
		mimeType:         stereoFile.MIMEType(f),
	}, nil
}

func (s fileSource) ID() artifact.ID {
	return s.id
}

func (s fileSource) Describe() source.Description {
	name := path.Base(s.config.Path)
	version := s.digestForVersion
	supplier := ""
	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}

		if a.Version != "" {
			version = a.Version
		}

		if a.Supplier != "" {
			supplier = a.Supplier
		}
	}
	return source.Description{
		ID:       string(s.id),
		Name:     name,
		Version:  version,
		Supplier: supplier,
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

	if isArchiveAnalysis := fi.IsDir(); isArchiveAnalysis {
		// this is an analysis of an archive file... we should scan the directory where the archive contents
		res, err := fileresolver.NewFromDirectory(s.analysisPath, "", exclusionFunctions...)
		if err != nil {
			return nil, fmt.Errorf("unable to create directory resolver: %w", err)
		}

		s.resolver = res
		return s.resolver, nil
	}

	// This is analysis of a single file. Use file indexer.
	res, err := fileresolver.NewFromFile(s.analysisPath, exclusionFunctions...)
	if err != nil {
		return nil, fmt.Errorf("unable to create file resolver: %w", err)
	}

	s.resolver = res
	return s.resolver, nil
}

func (s *fileSource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closer == nil {
		return nil
	}

	s.resolver = nil
	return s.closer()
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

// fileAnalysisPath returns the path given, or in the case the path is an archive, the location where the archive
// contents have been made available. A cleanup function is provided for any temp files created (if any).
// Users can disable unpacking archives, allowing individual cataloguers to extract them instead (where
// supported)
func fileAnalysisPath(path string, skipExtractArchive bool) (string, func() error, error) {
	cleanupFn := func() error { return nil }
	analysisPath := path

	if skipExtractArchive {
		return analysisPath, cleanupFn, nil
	}

	// Check if the given file is an archive by identifying its format
	ctx := context.Background()

	// Pass nil as stream to match by filename only
	format, _, err := archives.Identify(ctx, path, nil)
	if err != nil {
		// Not an archive format, just return the original path
		return analysisPath, cleanupFn, nil
	}

	// Check if it's actually an archive using the MIME type
	if !mimetype.IsArchive(format.MediaType()) {
		// Not an archive, just return the original path
		return analysisPath, cleanupFn, nil
	}

	// Extract the archive to a temp directory
	// Use the archives library to extract, which properly handles all formats
	analysisPath, cleanupFn, err = unarchiveToTmp(ctx, path, format)
	if err != nil {
		return "", nil, fmt.Errorf("unable to unarchive source file: %w", err)
	}

	log.Debugf("source path is an archive")

	return analysisPath, cleanupFn, nil
}

func digestOfFileContents(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return digest.SHA256.FromString(path).String()
	}
	defer f.Close()

	di, err := digest.SHA256.FromReader(f)
	if err != nil {
		return digest.SHA256.FromString(path).String()
	}

	return di.String()
}

// unarchiveToTmp extracts an archive to a temporary directory using the archives library.
// This function properly handles duplicate entries in archives (like tar) where "last entry wins".
func unarchiveToTmp(ctx context.Context, archivePath string, format archives.Format) (string, func() error, error) {
	tempDir, err := os.MkdirTemp("", "syft-archive-contents-")
	if err != nil {
		return "", func() error { return nil }, fmt.Errorf("unable to create tempdir for archive processing: %w", err)
	}

	cleanupFn := func() error {
		return os.RemoveAll(tempDir)
	}

	// Open the archive file
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		cleanupFn()
		return "", func() error { return nil }, fmt.Errorf("unable to open archive: %w", err)
	}
	defer archiveFile.Close()

	// Get the appropriate extractor for this format
	extractor, ok := format.(archives.Extractor)
	if !ok {
		cleanupFn()
		return "", func() error { return nil }, fmt.Errorf("format does not support extraction: %T", format)
	}

	// Extract all files from the archive
	// The FileHandler callback is called for each file in the archive
	err = extractor.Extract(ctx, archiveFile, func(ctx context.Context, fileInfo archives.FileInfo) error {
		// Skip directories - they'll be created as needed
		if fileInfo.IsDir() {
			return nil
		}

		destPath := filepath.Join(tempDir, fileInfo.NameInArchive)

		// Ensure the destination path is within tempDir (prevent path traversal)
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(tempDir)) {
			return nil // Skip this file
		}

		// Create parent directories if needed
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("unable to create parent directories for %q: %w", destPath, err)
		}

		// Open the file from the archive
		srcFile, err := fileInfo.Open()
		if err != nil {
			return fmt.Errorf("unable to open file %q from archive: %w", fileInfo.NameInArchive, err)
		}
		defer srcFile.Close()

		// Create/overwrite the destination file
		// Using os.Create ensures "last entry wins" for archives with duplicate paths
		dstFile, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("unable to create file %q: %w", destPath, err)
		}
		defer dstFile.Close()

		// Copy contents
		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return fmt.Errorf("unable to copy file %q: %w", fileInfo.NameInArchive, err)
		}

		return nil
	})
	if err != nil {
		cleanupFn()
		return "", func() error { return nil }, fmt.Errorf("unable to extract archive: %w", err)
	}

	return tempDir, cleanupFn, nil
}
