package deb

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/mitchellh/mapstructure"
)

// integrity check
var _ common.ParserFn = parseDpkgStatus

var errEndOfPackages = fmt.Errorf("no more packages to read")

// parseDpkgStatus is a parser function for Debian DB status contents, returning all Debian packages listed.
func parseDpkgStatus(_ string, reader io.Reader) ([]pkg.Package, error) {
	buffedReader := bufio.NewReader(reader)
	var packages = make([]pkg.Package, 0)

	for {
		entry, err := parseDpkgStatusEntry(buffedReader)
		if err != nil {
			if err == errEndOfPackages {
				break
			}
			return nil, err
		}
		packages = append(packages, pkg.Package{
			Name:         entry.Package,
			Version:      entry.Version,
			Type:         pkg.DebPkg,
			MetadataType: pkg.DpkgMetadataType,
			Metadata:     entry,
		})
	}

	return packages, nil
}

// parseDpkgStatusEntry returns an individual Dpkg entry, or returns errEndOfPackages if there are no more packages to parse from the reader.
func parseDpkgStatusEntry(reader *bufio.Reader) (entry pkg.DpkgMetadata, err error) {
	dpkgFields := make(map[string]string)
	var key string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return pkg.DpkgMetadata{}, errEndOfPackages
			}
			return pkg.DpkgMetadata{}, err
		}

		line = strings.TrimRight(line, "\n")

		// empty line indicates end of entry
		if len(line) == 0 {
			// if the entry has not started, keep parsing lines
			if len(dpkgFields) == 0 {
				continue
			}
			break
		}

		switch {
		case strings.HasPrefix(line, " "):
			// a field-body continuation
			if len(key) == 0 {
				return pkg.DpkgMetadata{}, fmt.Errorf("no match for continuation: line: '%s'", line)
			}

			val, ok := dpkgFields[key]
			if !ok {
				return pkg.DpkgMetadata{}, fmt.Errorf("no previous key exists, expecting: %s", key)
			}
			// concatenate onto previous value
			val = fmt.Sprintf("%s\n %s", val, strings.TrimSpace(line))
			dpkgFields[key] = val
		default:
			// parse a new key
			if i := strings.Index(line, ":"); i > 0 {
				key = strings.TrimSpace(line[0:i])
				val := strings.TrimSpace(line[i+1:])

				if _, ok := dpkgFields[key]; ok {
					return pkg.DpkgMetadata{}, fmt.Errorf("duplicate key discovered: %s", key)
				}

				dpkgFields[key] = val
			} else {
				return pkg.DpkgMetadata{}, fmt.Errorf("cannot parse field from line: '%s'", line)
			}
		}
	}

	err = mapstructure.Decode(dpkgFields, &entry)
	if err != nil {
		return pkg.DpkgMetadata{}, err
	}

	return entry, nil
}
