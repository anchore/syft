package arch

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/vbatts/go-mtree"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
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
func parseAlpmDB(_ context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	data, err := parseAlpmDBEntry(reader)
	if err != nil {
		return nil, nil, err
	}

	if data == nil {
		return nil, nil, nil
	}

	base := path.Dir(reader.RealPath)

	// replace the files found the pacman database with the files from the mtree These contain more metadata and
	// thus more useful.
	files, fileLoc := fetchPkgFiles(base, resolver)
	backups, backupLoc := fetchBackupFiles(base, resolver)

	var locs []file.Location
	if fileLoc != nil {
		locs = append(locs, fileLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
		data.Files = files
	}

	if backupLoc != nil {
		locs = append(locs, backupLoc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
		data.Backup = backups
	}

	if data.Package == "" {
		return nil, nil, nil
	}

	return []pkg.Package{
		newPackage(
			data,
			env.LinuxRelease,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			locs...,
		),
	}, nil, nil
}

func fetchPkgFiles(base string, resolver file.Resolver) ([]pkg.AlpmFileRecord, *file.Location) {
	// TODO: probably want to use MTREE and PKGINFO here
	target := path.Join(base, "mtree")

	loc, err := getLocation(target, resolver)
	if err != nil {
		log.WithFields("error", err, "path", target).Trace("failed to find mtree file")
		return []pkg.AlpmFileRecord{}, nil
	}
	if loc == nil {
		return []pkg.AlpmFileRecord{}, nil
	}

	reader, err := resolver.FileContentsByLocation(*loc)
	if err != nil {
		return []pkg.AlpmFileRecord{}, nil
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	pkgFiles, err := parseMtree(reader)
	if err != nil {
		log.WithFields("error", err, "path", target).Trace("failed to parse mtree file")
		return []pkg.AlpmFileRecord{}, nil
	}
	return pkgFiles, loc
}

func fetchBackupFiles(base string, resolver file.Resolver) ([]pkg.AlpmFileRecord, *file.Location) {
	// We only really do this to get any backup database entries from the files database
	target := filepath.Join(base, "files")

	loc, err := getLocation(target, resolver)
	if err != nil {
		log.WithFields("error", err, "path", target).Trace("failed to find alpm files")
		return []pkg.AlpmFileRecord{}, nil
	}
	if loc == nil {
		return []pkg.AlpmFileRecord{}, nil
	}

	reader, err := resolver.FileContentsByLocation(*loc)
	if err != nil {
		return []pkg.AlpmFileRecord{}, nil
	}
	defer internal.CloseAndLogError(reader, loc.RealPath)

	filesMetadata, err := parseAlpmDBEntry(reader)
	if err != nil {
		return []pkg.AlpmFileRecord{}, nil
	}
	if filesMetadata != nil {
		return filesMetadata.Backup, loc
	}
	return []pkg.AlpmFileRecord{}, loc
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
		for i := 0; i < len(data); i++ {
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

func getLocation(path string, resolver file.Resolver) (*file.Location, error) {
	locs, err := resolver.FilesByPath(path)
	if err != nil {
		return nil, err
	}

	if len(locs) == 0 {
		return nil, fmt.Errorf("could not find file: %s", path)
	}

	if len(locs) > 1 {
		log.WithFields("path", path).Trace("multiple files found for path, using first path")
	}
	return &locs[0], nil
}

func parseDatabase(b *bufio.Scanner) (*parsedData, error) {
	var err error
	pkgFields := make(map[string]interface{})
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
			var backup []map[string]interface{}
			for _, f := range strings.Split(value, "\n") {
				fields := strings.SplitN(f, "\t", 2)
				p := fmt.Sprintf("/%s", fields[0])
				if ok := ignoredFiles[p]; !ok {
					backup = append(backup, map[string]interface{}{
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

func parsePkgFiles(pkgFields map[string]interface{}) (*parsedData, error) {
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

func parseMtree(r io.Reader) ([]pkg.AlpmFileRecord, error) {
	var err error
	var entries []pkg.AlpmFileRecord

	r, err = gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	specDh, err := mtree.ParseSpec(r)
	if err != nil {
		return nil, err
	}
	for _, f := range specDh.Entries {
		var entry pkg.AlpmFileRecord
		entry.Digests = make([]file.Digest, 0)
		fileFields := make(map[string]interface{})
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
