package debian

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blakesmith/ar"
	"github.com/mholt/archives"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseDebArchive parses a Debian package archive (.deb) file and returns the packages it contains.
// A .deb file is an ar archive containing three main files:
// - debian-binary: Version of the .deb format (usually "2.0")
// - control.tar.gz/xz/zst: Contains package metadata (control file, md5sums, conffiles)
// - data.tar.gz/xz/zst: Contains the actual files to be installed (not processed by this cataloger)
//
// This function extracts and processes the control information to create package metadata.
func parseDebArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	arReader := ar.NewReader(reader)

	var metadata *pkg.DpkgArchiveEntry
	var licenses []string
	var unknownErr error
	var sawControl, sawData bool
	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read ar header: %w", err)
		}

		switch {
		// a .deb has exactly one control.tar.* and one data.tar.* member; anything past the first of
		// each is attacker-supplied filler that would otherwise buy a fresh decompression budget
		case !sawControl && strings.HasPrefix(header.Name, "control.tar"):
			sawControl = true
			// Decompress the control.tar.* file
			dcReader, err := decompressionStream(ctx, arReader, header.Name, maxControlTarSize)
			if err != nil {
				return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to decompress control.tar.* file: %w", err))
			}
			metadata, err = processControlTar(dcReader)
			switch {
			case err != nil && metadata == nil:
				return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to process control.tar.* file: %w", err))
			case err != nil:
				// metadata came back usable but incomplete (a clipped file listing); keep the package and
				// record why it is partial. The unknown above is removed from the SBOM by default once a
				// package is reported at these coordinates, so warn too since that's the channel a user
				// actually sees
				log.Warnf("deb archive %q: partial control.tar.* file: %v", reader.RealPath, err)
				unknownErr = unknown.Append(unknownErr, reader.Location, fmt.Errorf("partial control.tar.* file: %w", err))
			}
		case !sawData && strings.HasPrefix(header.Name, "data.tar"):
			sawData = true
			// Decompress the data.tar.* file
			dcReader, err := decompressionStream(ctx, arReader, header.Name, maxDataTarSize)
			if err != nil {
				return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to decompress data.tar.* file: %w", err))
			}
			licenses, err = processDataTar(dcReader)
			if err != nil {
				unknownErr = unknown.Append(unknownErr, reader.Location, fmt.Errorf("failed to process data.tar.* file: %w", err))
			}
		}

		if sawControl && sawData {
			break
		}
	}

	if metadata == nil {
		return nil, nil, unknown.New(reader.Location, fmt.Errorf("no application found described in .dpkg archive"))
	}

	// a partial parse still yields a usable package, so report what went wrong alongside it rather than
	// dropping either one
	return []pkg.Package{
		newDebArchivePackage(ctx, reader.Location, *metadata, licenses),
	}, nil, unknownErr
}

// this is the pattern you'd expect to see in a tar header for a debian package license file ()
var archiveHeaderLicensePathPattern = regexp.MustCompile(`^\.?/usr/share/doc/[^/]+/copyright$`)

func processDataTar(dcReader io.ReadCloser) ([]string, error) {
	defer internal.CloseAndLogError(dcReader, "")
	var licenses []string
	var copyrightFiles int

	tarReader := tar.NewReader(dcReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return licenses, err
		}

		// look for /usr/share/docs/*/copyright files, parse each one for license claims
		// TODO: in the future we can add archive sub indexes to the locations to see where within
		// the dpkg archive the license was found
		if archiveHeaderLicensePathPattern.MatchString(header.Name) {
			copyrightFiles++
			if copyrightFiles > maxCopyrightFiles {
				return licenses, fmt.Errorf("copyright file count exceeds %d; remaining files not read", maxCopyrightFiles)
			}
			licenses = append(licenses, parseLicensesFromCopyright(tarReader)...)
		}
	}

	return licenses, nil
}

// processControlTar always returns whatever metadata it managed to parse, even alongside a non-nil
// error. A non-nil error with non-nil metadata means the package is usable but incomplete (e.g. a
// clipped file listing); nil metadata means nothing usable was found and the caller should treat it
// as fatal.
func processControlTar(dcReader io.ReadCloser) (*pkg.DpkgArchiveEntry, error) {
	defer internal.CloseAndLogError(dcReader, "")

	tarReader := tar.NewReader(dcReader)

	var metadata *pkg.DpkgArchiveEntry
	var files []pkg.DpkgFileRecord
	var confFileRecords []pkg.DpkgFileRecord
	var listingErr error

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return metadata, fmt.Errorf("failed to read control tar: %w", err)
		}

		switch filepath.Base(header.Name) {
		case "control":
			// parseDpkgStatus already streams via bufio.Reader
			entries, err := parseDpkgStatus(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to parse control file: %w", err)
			}
			if len(entries) == 0 {
				return nil, fmt.Errorf("no package entries found in control file")
			}
			entry := pkg.DpkgArchiveEntry(entries[0].toDpkgEntry())
			metadata = &entry
		case "md5sums":
			// parseDpkgMD5Info streams via bufio.Scanner and reports its own clipping/scan errors
			var err error
			files, err = parseDpkgMD5Info(tarReader)
			listingErr = errors.Join(listingErr, err)
		case "conffiles":
			// parseDpkgConffileInfo streams via bufio.Scanner and reports its own clipping/scan errors
			var err error
			confFileRecords, err = parseDpkgConffileInfo(tarReader)
			listingErr = errors.Join(listingErr, err)
		}
	}

	if metadata == nil {
		return nil, fmt.Errorf("control file not found in archive")
	}

	if len(confFileRecords) > 0 && len(files) > 0 {
		configPaths := make(map[string]struct{}, len(confFileRecords))
		for _, cf := range confFileRecords {
			configPaths[cf.Path] = struct{}{}
		}
		for i, f := range files {
			if _, isConfig := configPaths[f.Path]; isConfig {
				files[i].IsConfigFile = true
			}
		}
	}

	metadata.Files = files

	// a clipped or unreadable file listing leaves the package usable, so hand both back and let the
	// caller decide
	return metadata, listingErr
}

// a .deb's member sizes are bounded by the archive, but what they decompress to is not: xz and zstd
// both exceed gzip's ~1032:1, so a few KB member can expand without limit. The two members get
// different budgets because they hold different things.
const (
	// control.tar holds only metadata (control, md5sums, conffiles). Even a package shipping a hundred
	// thousand files lands around 12MB of md5sums text.
	maxControlTarSize int64 = 16 * intFile.MB

	// data.tar is the package payload, which is legitimately large (texlive and cuda ship hundreds of
	// MB), so this is only here to stop the tar walk from spinning forever on a bomb. It mirrors the
	// perFileReadLimit already used for archive extraction in internal/file/copy.go.
	maxDataTarSize int64 = 2 * intFile.GB

	// a real .deb ships exactly one copyright file per package.
	maxCopyrightFiles = 1000
)

// sentinels so callers (and tests) can match with errors.Is instead of substring matching.
var (
	errDecompressedTooLarge = errors.New("decompressed stream is larger than the max allowed size")
	errClippedFileListing   = errors.New("file listing exceeds the max allowed entries")
)

func decompressionStream(ctx context.Context, r io.Reader, filePath string, maxDecompressed int64) (io.ReadCloser, error) {
	format, stream, err := archives.Identify(ctx, filePath, r)
	if err != nil {
		return nil, fmt.Errorf("failed to identify compression format: %w", err)
	}

	decompressor, ok := format.(archives.Decompressor)
	if !ok {
		return nil, fmt.Errorf("file format does not support decompression: %s", filePath)
	}

	rc, err := decompressor.OpenReader(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to create decompression reader: %w", err)
	}

	return newBoundedReadCloser(rc, maxDecompressed), nil
}

// boundedReadCloser fails the read past a byte budget rather than truncating.
//
// io.LimitedReader is the obvious thing to reach for here and is wrong for this: past its limit it
// just stops returning bytes, and both consumers of this are tar readers, which read a truncated
// stream as a clean end of archive. Together that emits a package silently missing files, which is
// the exact failure the bound exists to catch. The signal is recoverable by checking
// LimitedReader.N after the walk finishes (the same shape as safeCopy in internal/file/copy.go,
// which counts bytes off io.Copy), but nothing obliges a caller to write that check and a missed
// one is silent all over again. Erroring at the Read is the version that cannot be forgotten.
//
// net/http's MaxBytesReader has precisely these semantics and is stdlib, but reaching into the HTTP
// package to parse a .deb leaves the next reader wondering what it is doing here.
type boundedReadCloser struct {
	io.ReadCloser
	remaining int64
	limit     int64
}

func newBoundedReadCloser(rc io.ReadCloser, limit int64) *boundedReadCloser {
	// budget is one byte past the cap so a stream of exactly limit bytes still reaches EOF normally,
	// and only the byte after the cap trips the error. Clamp so a limit near math.MaxInt64 can't wrap
	// remaining negative and fail every read immediately.
	if limit < 0 || limit > math.MaxInt64-1 {
		limit = math.MaxInt64 - 1
	}
	return &boundedReadCloser{ReadCloser: rc, remaining: limit + 1, limit: limit}
}

func (b *boundedReadCloser) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, fmt.Errorf("%w (%d bytes)", errDecompressedTooLarge, b.limit)
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}
