package archive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/anchore/syft/internal"
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
	processed         map[processedKey]bool // archives we've already considered for extraction
	totalBytesWritten int64
	archiveNodes      []*archiveNode // for relationship tracking
	cleanups          []func()
	mu                sync.Mutex
}

// archiveNode tracks an extracted archive for relationship generation.
type archiveNode struct {
	location file.Location // where the archive is in the resolver
	fsID     string        // the filesystem ID assigned to this archive's contents
	depth    int
}

// processedKey identifies an archive location uniquely. We key the processed
// map on a struct (not a "<fsID>:<realPath>" string) because both fields can
// legally contain ':' — fsIDs are emitted as "archive:<hex>" and POSIX paths
// permit colons — so a string key would have an ambiguous boundary.
type processedKey struct {
	fsID     string
	realPath string
}

// NewOrchestrator creates an Orchestrator that manages archive extraction.
// The resolverFactory is used to build file.Resolvers for extracted archive directories.
func NewOrchestrator(baseResolver file.Resolver, cfg cataloging.ArchiveSearchConfig, tmpDir string, resolverFactory ResolverFactory) *Orchestrator {
	return &Orchestrator{
		composite:       NewCompositeResolver(baseResolver),
		extractors:      DefaultExtractors(),
		config:          cfg,
		tmpDir:          tmpDir,
		resolverFactory: resolverFactory,
		processed:       make(map[processedKey]bool),
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

	// build the list of extractors actually permitted by config — every
	// non-archive location in the resolver is going to pay a peek read against
	// these, so excluding disabled types up-front avoids reading files we
	// would only end up rejecting after detection.
	enabled := o.enabledExtractors()
	if len(enabled) == 0 {
		return 0
	}

	newArchives := 0

	// scan all locations in the current resolver for archives
	for loc := range o.composite.AllLocations(ctx) {
		if ctx.Err() != nil {
			break
		}

		// skip already-processed archives
		key := processedKey{fsID: loc.FileSystemID, realPath: loc.RealPath}
		if o.processed[key] {
			continue
		}

		// skip excluded extensions
		if IsExcludedExtension(loc.RealPath, o.config.ExcludeExtensions) {
			continue
		}

		// check if this location is an archive we can extract — peek a small
		// buffer rather than materializing the full file content, which would
		// be a full disk-to-disk copy of every non-archive file in the resolver.
		ext := o.detectFormat(ctx, loc, enabled)
		if ext == nil {
			continue
		}

		// mark as processed before extraction to avoid re-processing
		o.processed[key] = true

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

// enabledExtractors returns the subset of o.extractors whose corresponding
// config gate is on (IncludeIndexedArchives for ZipExtractor,
// IncludeUnindexedArchives for TarExtractor).
func (o *Orchestrator) enabledExtractors() []Extractor {
	var out []Extractor
	for _, ext := range o.extractors {
		switch ext.(type) {
		case *ZipExtractor:
			if o.config.IncludeIndexedArchives {
				out = append(out, ext)
			}
		case *TarExtractor:
			if o.config.IncludeUnindexedArchives {
				out = append(out, ext)
			}
		default:
			// unknown extractor types: include by default so plugin extractors
			// added in the future aren't silently disabled
			out = append(out, ext)
		}
	}
	return out
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

	// extractors need a file path, so materialize the archive contents to a temp file
	tmpPath, err := o.copyArchiveToTempFile(loc)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmpPath)

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

	result, err := ext.Extract(ctx, tmpPath, extractDir, limits)
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
	o.archiveNodes = append(o.archiveNodes, &archiveNode{
		location: loc,
		fsID:     fsID,
		depth:    depth,
	})

	log.WithFields(
		"archive", loc.Path(),
		"depth", depth,
		"files", result.FilesExtracted,
		"bytes", result.BytesWritten,
	).Debug("extracted archive contents")

	return true, nil
}

// formatProbeBytes is the size of the buffer peeked from each candidate file
// to decide whether it's an extractable archive.
//
// Single-step formats only need their magic bytes (ZIP: 4, gzip/bzip2/xz/zstd:
// 2-6, tar: a 512-byte first-block header). The size that matters is for
// compressed-tar without a recognized extension: there mholt/archives must
// gzip-decode our peek buffer and feed the result to tar.NewReader.Next(),
// which needs a full 512-byte tar header out the back. 4 KiB of compressed
// input gives gzip a comfortable margin and is still a single filesystem
// block read.
const formatProbeBytes = 4096

// detectFormat returns the first enabled extractor that can handle loc by
// peeking a small buffer of its contents (no full materialization). Returns
// nil when no extractor matches or when the file can't be opened. The caller
// is responsible for narrowing extractors to those permitted by config so we
// don't pay peek I/O for archive types that would only be rejected later.
func (o *Orchestrator) detectFormat(ctx context.Context, loc file.Location, extractors []Extractor) Extractor {
	reader, err := o.composite.FileContentsByLocation(loc)
	if err != nil {
		return nil
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	var peek [formatProbeBytes]byte
	n, _ := io.ReadFull(reader, peek[:])
	if n == 0 {
		return nil
	}
	for _, ext := range extractors {
		if ext.CanExtract(ctx, loc.RealPath, bytes.NewReader(peek[:n])) {
			return ext
		}
	}
	return nil
}

// copyArchiveToTempFile reads the archive contents from the resolver and writes them
// to a freshly-created temp file under o.tmpDir. The returned path must be removed
// by the caller (typically via defer).
func (o *Orchestrator) copyArchiveToTempFile(loc file.Location) (string, error) {
	reader, err := o.composite.FileContentsByLocation(loc)
	if err != nil {
		return "", fmt.Errorf("unable to get archive contents: %w", err)
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	tmpFile, err := os.CreateTemp(o.tmpDir, "archive-src-*")
	if err != nil {
		return "", fmt.Errorf("unable to create temp file: %w", err)
	}
	_, copyErr := safeIOCopy(tmpFile, reader)
	tmpFile.Close()
	if copyErr != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("unable to copy archive to temp: %w", copyErr)
	}
	return tmpFile.Name(), nil
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
