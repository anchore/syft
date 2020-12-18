package deb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/mitchellh/mapstructure"
)

var errEndOfPackages = fmt.Errorf("no more packages to read")

// parseDpkgStatus is a parser function for Debian DB status contents, returning all Debian packages listed.
func parseDpkgStatus(reader io.Reader) ([]pkg.Package, error) {
	buffedReader := bufio.NewReader(reader)
	var packages = make([]pkg.Package, 0)

	continueProcessing := true
	for continueProcessing {
		entry, err := parseDpkgStatusEntry(buffedReader)
		if err != nil {
			if errors.Is(err, errEndOfPackages) {
				continueProcessing = false
			} else {
				return nil, err
			}
		}

		if entry.Package != "" {
			packages = append(packages, pkg.Package{
				Name:         entry.Package,
				Version:      entry.Version,
				Type:         pkg.DebPkg,
				MetadataType: pkg.DpkgMetadataType,
				Metadata:     entry,
			})
		}
	}

	return packages, nil
}

// parseDpkgStatusEntry returns an individual Dpkg entry, or returns errEndOfPackages if there are no more packages to parse from the reader.
func parseDpkgStatusEntry(reader *bufio.Reader) (entry pkg.DpkgMetadata, err error) {
	dpkgFields := make(map[string]interface{})
	var retErr error
	var key string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				retErr = errEndOfPackages
				break
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
			var val interface{}
			key, val, err = handleNewKeyValue(line)
			if err != nil {
				return pkg.DpkgMetadata{}, err
			}

			if _, ok := dpkgFields[key]; ok {
				return pkg.DpkgMetadata{}, fmt.Errorf("duplicate key discovered: %s", key)
			}
			dpkgFields[key] = val
		}
	}

	err = mapstructure.Decode(dpkgFields, &entry)
	if err != nil {
		return pkg.DpkgMetadata{}, err
	}

	name, version := extractSourceVersion(entry.Source)
	if version != "" {
		entry.SourceVersion = version
		entry.Source = name
	}

	return entry, retErr
}


var sourceRegexp = regexp.MustCompile("(\\S+) \\((.*)\\)")

// If the source entry string is of the form "<name> (<version>)" then parse and return the components, if
// of the "<name>" form, then return name and nil
func extractSourceVersion(source string) (string, string) {
	//Special handling for the Source field since it has formatted data
	m := sourceRegexp.FindStringSubmatch(source)
	if len(m) == 3 {
		return m[1], m[2]
	}

	return m[1], ""
}

// handleNewKeyValue parse a new key-value pair from the given unprocessed line
func handleNewKeyValue(line string) (string, interface{}, error) {
	if i := strings.Index(line, ":"); i > 0 {
		var key = strings.TrimSpace(line[0:i])
		// mapstruct cant handle "-"
		key = strings.ReplaceAll(key, "-", "")
		val := strings.TrimSpace(line[i+1:])

		// further processing of values based on the key that was discovered
		switch key {
		case "InstalledSize":
			numVal, err := strconv.Atoi(val)
			if err != nil {
				return "", nil, fmt.Errorf("bad installed-size value=%q: %w", val, err)
			}
			return key, numVal, nil
		default:
			return key, val, nil
		}
	}

	return "", nil, fmt.Errorf("cannot parse field from line: '%s'", line)
}
