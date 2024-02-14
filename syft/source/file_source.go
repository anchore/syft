package source

import (
	"crypto"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/mholt/archiver/v3"
	"github.com/opencontainers/go-digest"

	stereoFile "github.com/anchore/stereoscope/pkg/file"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
)

var _ Source = (*FileSource)(nil)

type FileConfig struct {
	Path             string
	Exclude          ExcludeConfig
	DigestAlgorithms []crypto.Hash
	Alias            Alias
}

type FileSourceMetadata struct {
	Path     string        `json:"path" yaml:"path"`
	Digests  []file.Digest `json:"digests,omitempty" yaml:"digests,omitempty"`
	MIMEType string        `json:"mimeType" yaml:"mimeType"`
}

type FileSource struct {
	id               artifact.ID
	digestForVersion string
	config           FileConfig
	resolver         *fileresolver.Directory
	mutex            *sync.Mutex
	closer           func() error
	digests          []file.Digest
	mimeType         string
	analysisPath     string
}

func NewFromFile(cfg FileConfig) (*FileSource, error) {
	fileMeta, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("unable to stat path=%q: %w", cfg.Path, err)
	}

	if fileMeta.IsDir() {
		return nil, fmt.Errorf("given path is a directory: %q", cfg.Path)
	}

	analysisPath, cleanupFn := fileAnalysisPath(cfg.Path)

	var digests []file.Digest
	if len(cfg.DigestAlgorithms) > 0 {
		fh, err := os.Open(cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("unable to open file=%q: %w", cfg.Path, err)
		}

		defer fh.Close()

		digests, err = intFile.NewDigestsFromFile(fh, cfg.DigestAlgorithms)
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

	return &FileSource{
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
func deriveIDFromFile(cfg FileConfig) (artifact.ID, string) {
	d := digestOfFileContents(cfg.Path)
	info := d

	if !cfg.Alias.IsEmpty() {
		// if the user provided an alias, we want to consider that in the artifact ID. This way if the user
		// scans the same item but is considered to be logically different, then ID will express that.
		info += fmt.Sprintf(":%s@%s", cfg.Alias.Name, cfg.Alias.Version)
	}

	return artifactIDFromDigest(digest.SHA256.FromString(info).String()), d
}

func (s FileSource) ID() artifact.ID {
	return s.id
}

func (s FileSource) Describe() Description {
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
	return Description{
		ID:      string(s.id),
		Name:    name,
		Version: version,
		Metadata: FileSourceMetadata{
			Path:     s.config.Path,
			Digests:  s.digests,
			MIMEType: s.mimeType,
		},
	}
}

func (s FileSource) FileResolver(_ Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver != nil {
		return s.resolver, nil
	}

	exclusionFunctions, err := getDirectoryExclusionFunctions(s.analysisPath, s.config.Exclude.Paths)
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

	var res *fileresolver.Directory
	if isArchiveAnalysis {
		// this is an analysis of an archive file... we should scan the directory where the archive contents
		res, err = fileresolver.NewFromDirectory(s.analysisPath, "", exclusionFunctions...)
		if err != nil {
			return nil, fmt.Errorf("unable to create directory resolver: %w", err)
		}
	} else {
		// this is an analysis of a single file. We want to ultimately scan the directory that the file is in, but we
		// don't want to include any other files except this the given file.
		exclusionFunctions = append([]fileresolver.PathIndexVisitor{

			// note: we should exclude these kinds of paths first before considering any other user-provided exclusions
			func(_, p string, _ os.FileInfo, _ error) error {
				if p == absParentDir {
					// this is the root directory... always include it
					return nil
				}

				if filepath.Dir(p) != absParentDir {
					// we are no longer in the root directory containing the single file we want to scan...
					// we should skip the directory this path resides in entirely!
					return fs.SkipDir
				}

				if filepath.Base(p) != filepath.Base(s.config.Path) {
					// we're in the root directory, but this is not the file we want to scan...
					// we should selectively skip this file (not the directory we're in).
					return fileresolver.ErrSkipPath
				}
				return nil
			},
		}, exclusionFunctions...)

		res, err = fileresolver.NewFromDirectory(absParentDir, absParentDir, exclusionFunctions...)
		if err != nil {
			return nil, fmt.Errorf("unable to create directory resolver: %w", err)
		}
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

func (s *FileSource) Close() error {
	if s.closer == nil {
		return nil
	}
	s.resolver = nil
	return s.closer()
}

// fileAnalysisPath returns the path given, or in the case the path is an archive, the location where the archive
// contents have been made available. A cleanup function is provided for any temp files created (if any).
func fileAnalysisPath(path string) (string, func() error) {
	var analysisPath = path
	var cleanupFn = func() error { return nil }

	// if the given file is an archive (as indicated by the file extension and not MIME type) then unarchive it and
	// use the contents as the source. Note: this does NOT recursively unarchive contents, only the given path is
	// unarchived.
	envelopedUnarchiver, err := archiver.ByExtension(path)
	if unarchiver, ok := envelopedUnarchiver.(archiver.Unarchiver); err == nil && ok {
		if tar, ok := unarchiver.(*archiver.Tar); ok {
			// when tar files are extracted, if there are multiple entries at the same
			// location, the last entry wins
			// NOTE: this currently does not display any messages if an overwrite happens
			tar.OverwriteExisting = true
		}
		unarchivedPath, tmpCleanup, err := unarchiveToTmp(path, unarchiver)
		if err != nil {
			log.Warnf("file could not be unarchived: %+v", err)
		} else {
			log.Debugf("source path is an archive")
			analysisPath = unarchivedPath
		}
		if tmpCleanup != nil {
			cleanupFn = tmpCleanup
		}
	}

	return analysisPath, cleanupFn
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

func unarchiveToTmp(path string, unarchiver archiver.Unarchiver) (string, func() error, error) {
	tempDir, err := os.MkdirTemp("", "syft-archive-contents-")
	if err != nil {
		return "", func() error { return nil }, fmt.Errorf("unable to create tempdir for archive processing: %w", err)
	}

	cleanupFn := func() error {
		return os.RemoveAll(tempDir)
	}

	return tempDir, cleanupFn, unarchiver.Unarchive(path, tempDir)
}
