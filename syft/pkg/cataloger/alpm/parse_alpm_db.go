package alpm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/mitchellh/mapstructure"
)

// integrity check
var _ common.ParserFn = parseAlpmDB

func newAlpmDBPackage(d *pkg.AlpmMetadata) *pkg.Package {
	return &pkg.Package{
		Name:         d.Package,
		Version:      d.Version,
		Type:         "alpm",
		Licenses:     strings.Split(d.License, " "),
		MetadataType: pkg.AlpmMetadataType,
		Metadata:     *d,
	}
}

func newScanner(reader io.Reader) *bufio.Scanner {
	// This is taken from the apk parser
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

func parseDesc(b *bufio.Scanner) (*pkg.AlpmMetadata, error) {
	var entry pkg.AlpmMetadata
	pkgFields := make(map[string]interface{})
	for b.Scan() {
		fields := strings.SplitN(b.Text(), "\n", 2)

		// End of File
		if len(fields) == 1 {
			break
		}

		// The alpm database surrounds the keys with %.
		key := strings.Replace(fields[0], "%", "", -1)
		key = strings.ToLower(key)
		value := strings.TrimSpace(fields[1])

		switch key {
		case "version":
			ver := strings.SplitN(value, ":", 2)
			if len(ver) == 1 {
				pkgFields[key] = value
			} else {
				pkgFields["epoch"] = ver[0]
				pkgFields[key] = ver[1]
			}
		default:
			pkgFields[key] = value
		}
	}
	if err := mapstructure.Decode(pkgFields, &entry); err != nil {
		return nil, fmt.Errorf("unable to parse ALPM metadata: %w", err)
	}
	if entry.Package == "" {
		return nil, nil
	}
	return &entry, nil
}

func parseFiles(b *bufio.Scanner) []pkg.AlpmFileRecord {
	var entries []pkg.AlpmFileRecord
	for b.Scan() {
		if b.Text() == "" {
			break
		}
		fields := strings.SplitN(b.Text(), "\n", 2)
		if fields[0] != "%FILES%" {
			return nil
		}
		for _, f := range strings.Split(fields[1], "\n") {
			entries = append(entries, pkg.AlpmFileRecord{Path: f})
		}
	}
	return entries
}

func parseAlpmDB(f string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	base := filepath.Dir(f)
	scanner := newScanner(reader)
	metadata, err := parseDesc(scanner)
	if err != nil {
		return nil, nil, err
	}
	if metadata == nil {
		return nil, nil, nil
	}

	filesIndex := filepath.Join(base, "files")
	r, err := os.Open(filesIndex)
	if err == nil {
		// TODO: Figure out why we sometimes don't  find the "files" file
		scanner = newScanner(r)
		metadata.Files = parseFiles(scanner)
	}

	return []*pkg.Package{newAlpmDBPackage(metadata)}, nil, nil
}
