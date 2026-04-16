package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
)

// ResolverFactory creates a file.Resolver for a directory path.
// This is injectable to avoid direct dependency on syft/internal/fileresolver.
type ResolverFactory func(root string) (file.Resolver, error)

// Orchestrator manages iterative archive extraction and cataloging. It discovers
// archives in the file resolver, extracts them, builds child resolvers for their
// contents, and tracks the relationships between archives and their contents.
type Orchestrator struct {
	composite       *CompositeResolver
	extractors      []Extractor
	config          cataloging.ArchiveSearchConfig
	tmpDir          string
	resolverFactory ResolverFactory

	// tracking state
	processed         map[string]bool // archive paths already extracted (keyed by fsID:realPath)
	totalBytesWritten int64
	archiveNodes      []*archiveNode // for relationship tracking
	cleanups          []func()
	mu                sync.Mutex
}

// archiveNode tracks an extracted archive for relationship generation.
type archiveNode struct {
	location    file.Location // where the archive is in the resolver
	fsID        string        // the filesystem ID assigned to this archive's contents
	depth       int
	parentFSID  string // fsID of the parent archive (empty for top-level)
}

// NewOrchestrator creates an Orchestrator that manages archive extraction across
// the given base resolver.
// NewOrchestrator creates an Orchestrator that manages archive extraction.
// The resolverFactory is used to build file.Resolvers for extracted archive directories.
func NewOrchestrator(baseResolver file.Resolver, cfg cataloging.ArchiveSearchConfig, tmpDir string, resolverFactory ResolverFactory) *Orchestrator {
	return &Orchestrator{
		composite:       NewCompositeResolver(baseResolver),
		extractors:      DefaultExtractors(),
		config:          cfg,
		tmpDir:          tmpDir,
		resolverFactory: resolverFactory,
		processed:       make(map[string]bool),
	}
}

// Resolver returns the composite resolver that includes all extracted archive contents.
func (o *Orchestrator) Resolver() *CompositeResolver {
	return o.composite
}

// DiscoverAndExtract finds archives in the current resolver view, extracts them,
// and adds their contents as child resolvers. Returns the number of new archives extracted.
// The depth parameter indicates the current nesting depth (0 = scanning base filesystem).
func (o *Orchestrator) DiscoverAndExtract(ctx context.Context, depth int) int {
	if depth >= o.config.MaxDepth {
		return 0
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if o.config.MaxTotalExtractionBytes > 0 && o.totalBytesWritten >= o.config.MaxTotalExtractionBytes {
		log.Debug("archive orchestrator: total extraction size limit reached, stopping")
		return 0
	}

	newArchives := 0

	// scan all locations in the current resolver for archives
	for loc := range o.composite.AllLocations(ctx) {
		if ctx.Err() != nil {
			break
		}

		// skip non-files and already-processed archives
		key := loc.FileSystemID + ":" + loc.RealPath
		if o.processed[key] {
			continue
		}

		// skip excluded extensions
		if IsExcludedExtension(loc.RealPath, o.config.ExcludeExtensions) {
			continue
		}

		// check if this location is an archive we can extract
		// we need the real filesystem path to check the format
		realPath, cleanup, err := o.materializePath(loc)
		if err != nil {
			continue
		}

		ext := FindExtractor(ctx, o.extractors, realPath)
		if cleanup != nil {
			cleanup()
		}
		if ext == nil {
			continue
		}

		// mark as processed before extraction to avoid re-processing
		o.processed[key] = true

		// check archive type config
		switch ext.(type) {
		case *ZipExtractor:
			if !o.config.IncludeIndexedArchives {
				continue
			}
		case *TarExtractor:
			if !o.config.IncludeUnindexedArchives {
				continue
			}
		}

		// extract the archive
		extracted, err := o.extractArchive(ctx, ext, loc, depth+1)
		if err != nil {
			log.WithFields("archive", loc.Path(), "error", err).Debug("failed to extract archive")
			continue
		}
		if extracted {
			newArchives++
		}
	}

	return newArchives
}

// extractArchive extracts a single archive and registers its contents as a child resolver.
func (o *Orchestrator) extractArchive(ctx context.Context, ext Extractor, loc file.Location, depth int) (bool, error) {
	// create a temp dir for this archive's contents
	extractDir, err := os.MkdirTemp(o.tmpDir, fmt.Sprintf("archive-depth%d-*", depth))
	if err != nil {
		return false, fmt.Errorf("unable to create temp dir: %w", err)
	}
	o.cleanups = append(o.cleanups, func() {
		os.RemoveAll(extractDir)
	})

	// get the real file content
	reader, err := o.composite.FileContentsByLocation(loc)
	if err != nil {
		return false, fmt.Errorf("unable to get archive contents: %w", err)
	}

	// write to a temp file for extraction (extractors need a file path)
	tmpFile, err := os.CreateTemp(o.tmpDir, "archive-src-*")
	if err != nil {
		reader.Close()
		return false, fmt.Errorf("unable to create temp file: %w", err)
	}
	_, copyErr := safeIOCopy(tmpFile, reader)
	reader.Close()
	tmpFile.Close()
	if copyErr != nil {
		os.Remove(tmpFile.Name())
		return false, fmt.Errorf("unable to copy archive to temp: %w", copyErr)
	}
	defer os.Remove(tmpFile.Name())

	// calculate remaining budget
	limits := ExtractionLimits{
		MaxExtractionSizeBytes: o.config.MaxExtractionSizeBytes,
		MaxFileCount:           o.config.MaxFileCount,
	}
	if o.config.MaxTotalExtractionBytes > 0 {
		remaining := o.config.MaxTotalExtractionBytes - o.totalBytesWritten
		if remaining <= 0 {
			return false, fmt.Errorf("total extraction budget exhausted")
		}
		if limits.MaxExtractionSizeBytes == 0 || remaining < limits.MaxExtractionSizeBytes {
			limits.MaxExtractionSizeBytes = remaining
		}
	}

	result, err := ext.Extract(ctx, tmpFile.Name(), extractDir, limits)
	if err != nil {
		log.WithFields("archive", loc.Path(), "error", err).Debug("archive extraction stopped")
		// partial extraction is still useful, continue if we got some files
		if result.FilesExtracted == 0 {
			return false, err
		}
	}

	o.totalBytesWritten += result.BytesWritten

	if result.FilesExtracted == 0 {
		return false, nil
	}

	// build a directory resolver for the extracted contents
	childResolver, resolverErr := o.resolverFactory(extractDir)
	if resolverErr != nil {
		return false, fmt.Errorf("unable to build resolver for extracted archive: %w", resolverErr)
	}

	fsID := o.composite.AddChild(childResolver, loc, depth)

	// track for relationship generation
	parentFSID := loc.FileSystemID
	o.archiveNodes = append(o.archiveNodes, &archiveNode{
		location:   loc,
		fsID:       fsID,
		depth:      depth,
		parentFSID: parentFSID,
	})

	log.WithFields(
		"archive", loc.Path(),
		"depth", depth,
		"files", result.FilesExtracted,
		"bytes", result.BytesWritten,
	).Debug("extracted archive contents")

	return true, nil
}

// materializePath resolves a location to a real filesystem path by extracting
// the file content to a temporary file. This is needed because archive format
// detection requires a seekable file.
func (o *Orchestrator) materializePath(loc file.Location) (string, func(), error) {
	reader, err := o.composite.FileContentsByLocation(loc)
	if err != nil {
		return "", nil, err
	}
	defer reader.Close()

	ext := filepath.Ext(loc.RealPath)
	tmpFile, err := os.CreateTemp(o.tmpDir, "probe-*"+ext)
	if err != nil {
		return "", nil, err
	}

	if _, err := safeIOCopy(tmpFile, reader); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", nil, err
	}
	tmpFile.Close()

	cleanup := func() {
		os.Remove(tmpFile.Name())
	}
	return tmpFile.Name(), cleanup, nil
}

// Relationships returns the archive containment relationships discovered during extraction.
func (o *Orchestrator) Relationships() []artifact.Relationship {
	o.mu.Lock()
	defer o.mu.Unlock()

	var rels []artifact.Relationship
	for _, node := range o.archiveNodes {
		// Create a "contains" relationship: the archive contains its extracted content
		// The archive file (identified by its coordinates) contains the child filesystem
		rels = append(rels, artifact.Relationship{
			From: node.location.Coordinates,
			To:   file.Coordinates{RealPath: "/", FileSystemID: node.fsID},
			Type: artifact.ContainsRelationship,
		})
	}
	return rels
}

// Cleanup removes all temporary directories created during extraction.
func (o *Orchestrator) Cleanup() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, cleanup := range o.cleanups {
		cleanup()
	}
	o.cleanups = nil
}

// safeIOCopy copies with a size limit to prevent decompression bombs.
func safeIOCopy(dst *os.File, src interface{ Read([]byte) (int, error) }) (int64, error) {
	const maxCopySize = 2 * 1024 * 1024 * 1024 // 2GB
	return limitedCopy(dst, src, maxCopySize)
}

func limitedCopy(dst *os.File, src interface{ Read([]byte) (int, error) }, limit int64) (int64, error) {
	n, err := copyN(dst, src, limit)
	if n >= limit {
		return n, fmt.Errorf("copy size limit reached (%d bytes)", limit)
	}
	return n, err
}

func copyN(dst *os.File, src interface{ Read([]byte) (int, error) }, limit int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for written < limit {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			written += int64(nw)
			if writeErr != nil {
				return written, writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
	return written, nil
}
