package arch

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/vbatts/go-mtree"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseAlpmDB

var (
	ignoredFiles = map[string]bool{
		"/set":       true,
		".BUILDINFO": true,
		".PKGINFO":   true,
		"":           true,
	}
)

type parsedData struct {
	Licenses        string `mapstructure:"license"`
	pkg.AlpmDBEntry `mapstructure:",squash"`
}

// parseAlpmDB parses the arch linux pacman database flat-files and returns the packages and relationships found within.
func parseAlpmDB(ctx context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var errs error

	data, err := parseAlpmDBEntry(reader)
	if err != nil {
		return nil, nil, err
	}

	if data == nil {
		return nil, nil, nil
	}

	base := path.Dir(reader.RealPath)

	var locs []file.Location

	// replace the files found the pacman database with the files from the mtree These contain more metadata and
	// thus more useful.
	files, fileLoc, err := fetchPkgFiles(base, resolver)
	errs = unknown.Join(errs, err)
	if err == nil {
		locs = append(locs, fileLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
		data.Files = files
	}
	backups, backupLoc, err := fetchBackupFiles(base, resolver)
	errs = unknown.Join(errs, err)
	if err == nil {
		locs = append(locs, backupLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
		data.Backup = backups
	}

	if data.Package == "" {
		return nil, nil, errs
	}

	return []pkg.Package{
		newPackage(
			ctx,
			data,
			env.LinuxRelease,
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			locs...,
		),
	}, nil, errs
}

func fetchPkgFiles(base string, resolver file.Resolver) ([]pkg.AlpmFileRecord, file.Location, error) {
	// TODO: probably want to use MTREE and PKGINFO here
	target := path.Join(base, "mtree")

	loc, err := getLocation(target, resolver)
	if err != nil {
		log.WithFields("error", err, "path", target).Trace("failed to find mtree file")
		return []pkg.AlpmFileRecord{}, loc, unknown.New(loc, fmt.Errorf("failed to find mtree file: %w", err))
	}
	reader, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return []pkg.AlpmFileRecord{}, loc, unknown.New(loc, fmt.Errorf("failed to get contents: %w", err))
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	pkgFiles, err := parseMtree(reader)
	if err != nil {
		log.WithFields("error", err, "path", target).Trace("failed to parse mtree file")
		return []pkg.AlpmFileRecord{}, loc, unknown.New(loc, fmt.Errorf("failed to parse mtree: %w", err))
	}
	return pkgFiles, loc, nil
}

func fetchBackupFiles(base string, resolver file.Resolver) ([]pkg.AlpmFileRecord, file.Location, error) {
	// We only really do this to get any backup database entries from the files database
	target := filepath.Join(base, "files")

	loc, err := getLocation(target, resolver)
	if err != nil {
		log.WithFields("error", err, "path", target).Trace("failed to find alpm files")
		return []pkg.AlpmFileRecord{}, loc, unknown.New(loc, fmt.Errorf("failed to find alpm files: %w", err))
	}

	reader, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return []pkg.AlpmFileRecord{}, loc, unknown.New(loc, fmt.Errorf("failed to get contents: %w", err))
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	filesMetadata, err := parseAlpmDBEntry(reader)
	if err != nil {
		return []pkg.AlpmFileRecord{}, loc, unknown.New(loc, fmt.Errorf("failed to parse alpm db entry: %w", err))
	}
	if filesMetadata != nil {
		return filesMetadata.Backup, loc, nil
	}
	return []pkg.AlpmFileRecord{}, loc, nil
}

func parseAlpmDBEntry(reader io.Reader) (*parsedData, error) {
	scanner := newScanner(reader)
	metadata, err := parseDatabase(scanner)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

func newScanner(reader io.Reader) *bufio.Scanner {
	// This is taken from the apk parser
	// https://github.com/anchore/syft/blob/v0.47.0/syft/pkg/cataloger/apkdb/parse_apk_db.go#L37
	const maxScannerCapacity = 1024 * 1024
	bufScan := make([]byte, maxScannerCapacity)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(bufScan, maxScannerCapacity)
	onDoubleLF := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		for i := range data {
			if i > 0 && data[i-1] == '\n' && data[i] == '\n' {
				return i + 1, data[:i-1], nil
			}
		}
		if !atEOF {
			return 0, nil, nil
		}
		// deliver the last token (which could be an empty string)
		return 0, data, bufio.ErrFinalToken
	}

	scanner.Split(onDoubleLF)
	return scanner
}

func getLocation(path string, resolver file.Resolver) (file.Location, error) {
	loc := file.NewLocation(path)
	locs, err := resolver.FilesByPath(path)
	if err != nil {
		return loc, err
	}

	if len(locs) == 0 {
		return loc, fmt.Errorf("could not find file: %s", path)
	}

	if len(locs) > 1 {
		log.WithFields("path", path).Trace("multiple files found for path, using first path")
	}
	return locs[0], nil
}

func parseDatabase(b *bufio.Scanner) (*parsedData, error) {
	var err error
	pkgFields := make(map[string]any)
	for b.Scan() {
		fields := strings.SplitN(b.Text(), "\n", 2)

		// End of File
		if len(fields) == 1 {
			break
		}

		// The alpm database surrounds the keys with %.
		key := strings.ReplaceAll(fields[0], "%", "")
		key = strings.ToLower(key)
		value := strings.TrimSpace(fields[1])

		switch key {
		case "files":
			var files []map[string]string
			for _, f := range strings.Split(value, "\n") {
				p := fmt.Sprintf("/%s", f)
				if ok := ignoredFiles[p]; !ok {
					files = append(files, map[string]string{"path": p})
				}
			}
			pkgFields[key] = files
		case "backup":
			var backup []map[string]any
			for _, f := range strings.Split(value, "\n") {
				fields := strings.SplitN(f, "\t", 2)
				// a line without the tab would index past the end of the split
				if len(fields) < 2 {
					continue
				}
				p := fmt.Sprintf("/%s", fields[0])
				if ok := ignoredFiles[p]; !ok {
					backup = append(backup, map[string]any{
						"path": p,
						"digests": []file.Digest{{
							Algorithm: "md5",
							Value:     fields[1],
						}}})
				}
			}
			pkgFields[key] = backup
		case "depends", "provides":
			pkgFields[key] = processLibrarySpecs(value)
		case "reason":
			fallthrough
		case "size":
			pkgFields[key], err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s to integer", value)
			}
		default:
			pkgFields[key] = value
		}
	}

	// without this, a field over the scanner's 1MB token cap ends the scan and hands back a
	// half-populated package with a nil error
	if err := b.Err(); err != nil {
		return nil, err
	}

	return parsePkgFiles(pkgFields)
}

func processLibrarySpecs(value string) []string {
	lines := strings.Split(value, "\n")
	librarySpecs := make([]string, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		librarySpecs = append(librarySpecs, line)
	}
	return librarySpecs
}

func parsePkgFiles(pkgFields map[string]any) (*parsedData, error) {
	var entry parsedData
	if err := mapstructure.Decode(pkgFields, &entry); err != nil {
		return nil, fmt.Errorf("unable to parse ALPM metadata: %w", err)
	}

	if entry.Backup == nil {
		entry.Backup = make([]pkg.AlpmFileRecord, 0)
	}

	if entry.Files == nil {
		entry.Files = make([]pkg.AlpmFileRecord, 0)
	}

	if entry.Package == "" && len(entry.Files) == 0 && len(entry.Backup) == 0 {
		return nil, nil
	}
	return &entry, nil
}

// maxMtreeSize bounds the decompressed listing, sized against texlive-fontsextra (the largest
// package Arch ships) whose listing runs 16 to 27MB.
//
// This bounds bytes, not heap. go-mtree allocates per whitespace-delimited field, so a crafted
// listing of minimal fields still costs roughly a gigabyte here, times cataloger parallelism.
const maxMtreeSize = 64 * intFile.MB

// maxMtreeLines bounds retained entries, which the byte cap does not: go-mtree keeps a 128 byte
// entry per line, blank lines included. 300k is ~2.8x the largest package Arch ships.
const maxMtreeLines = 300_000

var (
	errMtreeTooLarge      = errors.New("mtree file is larger than the max allowed size")
	errTooManyMtreeLines  = errors.New("mtree file has more lines than allowed")
	errMtreeLineContinued = errors.New("mtree file uses line continuations")
)

// lineLimitedReader fails the read once the stream carries more than max newlines, or a line
// continuation. Counting as the bytes flow is what bounds the entries: the parser materializes one
// per line before returning any of them.
//
// Continuations are refused rather than counted. go-mtree collapses a line ending in a backslash
// into the next one with a quadratic string concat, so the cost is lines times bytes and neither
// bound above can see it. Its scanner drops a trailing carriage return before testing for the
// backslash, so both line endings count. Nothing that writes these listings emits continuations.
//
// A tripped bound is latched, so a caller that reads past the first error does not come back clean.
type lineLimitedReader struct {
	reader   io.Reader
	lines    int
	max      int
	lastByte byte
	err      error
}

func (l *lineLimitedReader) Read(p []byte) (int, error) {
	if l.err != nil {
		return 0, l.err
	}

	n, err := l.reader.Read(p)

	// prev carries the previous chunk's last byte, so a backslash and the line ending it continues
	// are still seen when a read splits them
	prev := l.lastByte
	for _, c := range p[:n] {
		if (c == '\n' || c == '\r') && prev == '\\' {
			l.err = errMtreeLineContinued
			return n, l.err
		}
		if c == '\n' {
			l.lines++
		}
		prev = c
	}
	l.lastByte = prev

	if l.lines > l.max {
		l.err = fmt.Errorf("%w (max %d)", errTooManyMtreeLines, l.max)
		return n, l.err
	}

	return n, err
}

func parseMtree(r io.Reader) ([]pkg.AlpmFileRecord, error) {
	return parseMtreeWithLimits(r, maxMtreeSize, maxMtreeLines)
}

// parseMtreeWithLimits lets the boundary tests be exact without allocating up to the shipped caps.
// maxSize must be below math.MaxInt64, since the limiter carries a byte of headroom.
func parseMtreeWithLimits(r io.Reader, maxSize int64, maxLines int) ([]pkg.AlpmFileRecord, error) {
	var entries []pkg.AlpmFileRecord

	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(gzReader, "mtree")

	// the line cap trips while the listing streams. The byte cap cannot: io.LimitedReader signals a
	// drained budget with io.EOF, which the parser reads as a complete listing, so it is checked
	// after the parse. The extra byte is what tells a drained budget from a listing ending at the cap.
	sizeLimited := &io.LimitedReader{R: gzReader, N: maxSize + 1}
	specDh, err := mtree.ParseSpec(&lineLimitedReader{reader: sizeLimited, max: maxLines})

	// ahead of err: a drained budget means the parser saw only part of the listing, whatever it returned
	if sizeLimited.N <= 0 {
		return nil, fmt.Errorf("%w (%d bytes)", errMtreeTooLarge, maxSize)
	}
	if err != nil {
		return nil, err
	}
	for _, f := range specDh.Entries {
		var entry pkg.AlpmFileRecord
		entry.Digests = make([]file.Digest, 0)
		fileFields := make(map[string]any)
		if ok := ignoredFiles[f.Name]; ok {
			continue
		}
		path := fmt.Sprintf("/%s", f.Name)
		fileFields["path"] = path
		for _, kv := range f.Keywords {
			kw := string(kv.Keyword())
			switch kw {
			case "time":
				// All unix timestamps have a .0 suffixs.
				v := strings.Split(kv.Value(), ".")
				i, _ := strconv.ParseInt(v[0], 10, 64)
				tm := time.Unix(i, 0)
				fileFields[kw] = tm
			case "sha256digest":
				entry.Digests = append(entry.Digests, file.Digest{
					Algorithm: "sha256",
					Value:     kv.Value(),
				})
			case "md5digest":
				entry.Digests = append(entry.Digests, file.Digest{
					Algorithm: "md5",
					Value:     kv.Value(),
				})
			default:
				fileFields[kw] = kv.Value()
			}
		}
		if err := mapstructure.Decode(fileFields, &entry); err != nil {
			return nil, fmt.Errorf("unable to parse ALPM mtree data: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
