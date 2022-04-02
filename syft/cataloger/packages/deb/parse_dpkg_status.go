package deb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/dustin/go-humanize"
	"github.com/mitchellh/mapstructure"
)

var (
	errEndOfPackages = fmt.Errorf("no more packages to read")
	sourceRegexp     = regexp.MustCompile(`(?P<name>\S+)( \((?P<version>.*)\))?`)
)

func newDpkgPackage(d pkg.DpkgMetadata) pkg.Package {
	return pkg.Package{
		Name:         d.Package,
		Version:      d.Version,
		Type:         pkg.DebPkg,
		MetadataType: pkg.DpkgMetadataType,
		Metadata:     d,
	}
}

// parseDpkgStatus is a parser function for Debian DB status contents, returning all Debian packages listed.
func parseDpkgStatus(reader io.Reader) ([]pkg.Package, error) {
	buffedReader := bufio.NewReader(reader)
	var packages []pkg.Package

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
			packages = append(packages, newDpkgPackage(entry))
		}
	}

	return packages, nil
}

// parseDpkgStatusEntry returns an individual Dpkg entry, or returns errEndOfPackages if there are no more packages to parse from the reader.
func parseDpkgStatusEntry(reader *bufio.Reader) (pkg.DpkgMetadata, error) {
	var retErr error
	dpkgFields, err := extractAllFields(reader)
	if err != nil {
		if !errors.Is(err, errEndOfPackages) {
			return pkg.DpkgMetadata{}, err
		}
		retErr = err
	}

	entry := pkg.DpkgMetadata{
		// ensure the default value for a collection is never nil since this may be shown as JSON
		Files: make([]pkg.DpkgFileRecord, 0),
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

	// there may be an optional conffiles section that we should persist as files
	if conffilesSection, exists := dpkgFields["Conffiles"]; exists && conffilesSection != nil {
		if sectionStr, ok := conffilesSection.(string); ok {
			entry.Files = parseDpkgConffileInfo(strings.NewReader(sectionStr))
		}
	}

	return entry, retErr
}

func extractAllFields(reader *bufio.Reader) (map[string]interface{}, error) {
	dpkgFields := make(map[string]interface{})
	var key string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return dpkgFields, errEndOfPackages
			}
			return nil, err
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
				return nil, fmt.Errorf("no match for continuation: line: '%s'", line)
			}

			val, ok := dpkgFields[key]
			if !ok {
				return nil, fmt.Errorf("no previous key exists, expecting: %s", key)
			}
			// concatenate onto previous value
			val = fmt.Sprintf("%s\n %s", val, strings.TrimSpace(line))
			dpkgFields[key] = val
		default:
			// parse a new key
			var val interface{}
			key, val, err = handleNewKeyValue(line)
			if err != nil {
				log.Warnf("parsing dpkg status: extracting key-value from line: %s err: %v", line, err)
				continue
			}

			if _, ok := dpkgFields[key]; ok {
				return nil, fmt.Errorf("duplicate key discovered: %s", key)
			}
			dpkgFields[key] = val
		}
	}
	return dpkgFields, nil
}

// If the source entry string is of the form "<name> (<version>)" then parse and return the components, if
// of the "<name>" form, then return name and nil
func extractSourceVersion(source string) (string, string) {
	// special handling for the Source field since it has formatted data
	match := internal.MatchNamedCaptureGroups(sourceRegexp, source)
	return match["name"], match["version"]
}

// handleNewKeyValue parse a new key-value pair from the given unprocessed line
func handleNewKeyValue(line string) (key string, val interface{}, err error) {
	if i := strings.Index(line, ":"); i > 0 {
		key = strings.TrimSpace(line[0:i])
		// mapstruct cant handle "-"
		key = strings.ReplaceAll(key, "-", "")
		val := strings.TrimSpace(line[i+1:])

		// further processing of values based on the key that was discovered
		switch key {
		case "InstalledSize":
			s, err := humanize.ParseBytes(val)
			if err != nil {
				return "", nil, fmt.Errorf("bad installed-size value=%q: %w", val, err)
			}
			return key, int(s), nil
		default:
			return key, val, nil
		}
	}

	return "", nil, fmt.Errorf("cannot parse field from line: '%s'", line)
}
