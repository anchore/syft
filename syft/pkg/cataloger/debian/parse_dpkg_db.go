package debian

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	errEndOfPackages = fmt.Errorf("no more packages to read")
	sourceRegexp     = regexp.MustCompile(`(?P<name>\S+)( \((?P<version>.*)\))?`)
)

// parseDpkgDB reads a dpkg database "status" file (and surrounding data files) and returns the packages and relationships found.
func parseDpkgDB(_ context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	metadata, err := parseDpkgStatus(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to catalog dpkg DB=%q: %w", reader.RealPath, err)
	}

	var pkgs []pkg.Package
	for _, m := range metadata {
		pkgs = append(pkgs, newDpkgPackage(m, reader.Location, resolver, env.LinuxRelease))
	}

	return pkgs, nil, nil
}

// parseDpkgStatus is a parser function for Debian DB status contents, returning all Debian packages listed.
func parseDpkgStatus(reader io.Reader) ([]pkg.DpkgDBEntry, error) {
	buffedReader := bufio.NewReader(reader)
	var metadata []pkg.DpkgDBEntry

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
		if entry == nil {
			continue
		}

		metadata = append(metadata, *entry)
	}

	return metadata, nil
}

// dpkgExtractedMetadata is an adapter struct to capture the fields from the dpkg status file, however, the final
// pkg.DpkgMetadata struct has different types for some fields (e.g. Provides, Depends, and PreDepends is []string, not a string).
type dpkgExtractedMetadata struct {
	Package       string `mapstructure:"Package"`
	Source        string `mapstructure:"Source"`
	Version       string `mapstructure:"Version"`
	SourceVersion string `mapstructure:"SourceVersion"`
	Architecture  string `mapstructure:"Architecture"`
	Maintainer    string `mapstructure:"Maintainer"`
	InstalledSize int    `mapstructure:"InstalledSize"`
	Description   string `mapstructure:"Description"`
	Provides      string `mapstructure:"Provides"`
	Depends       string `mapstructure:"Depends"`
	PreDepends    string `mapstructure:"PreDepends"` // note: original doc is Pre-Depends
}

// parseDpkgStatusEntry returns an individual Dpkg entry, or returns errEndOfPackages if there are no more packages to parse from the reader.
func parseDpkgStatusEntry(reader *bufio.Reader) (*pkg.DpkgDBEntry, error) {
	var retErr error
	dpkgFields, err := extractAllFields(reader)
	if err != nil {
		if !errors.Is(err, errEndOfPackages) {
			return nil, err
		}
		if len(dpkgFields) == 0 {
			return nil, err
		}
		retErr = err
	}

	raw := dpkgExtractedMetadata{}
	err = mapstructure.Decode(dpkgFields, &raw)
	if err != nil {
		return nil, err
	}

	sourceName, sourceVersion := extractSourceVersion(raw.Source)
	if sourceVersion != "" {
		raw.SourceVersion = sourceVersion
		raw.Source = sourceName
	}

	if raw.Package == "" {
		return nil, retErr
	}

	entry := pkg.DpkgDBEntry{
		Package:       raw.Package,
		Source:        raw.Source,
		Version:       raw.Version,
		SourceVersion: raw.SourceVersion,
		Architecture:  raw.Architecture,
		Maintainer:    raw.Maintainer,
		InstalledSize: raw.InstalledSize,
		Description:   raw.Description,
		Provides:      splitPkgList(raw.Provides),
		Depends:       splitPkgList(raw.Depends),
		PreDepends:    splitPkgList(raw.PreDepends),
	}

	// there may be an optional conffiles section that we should persist as files
	if conffilesSection, exists := dpkgFields["Conffiles"]; exists && conffilesSection != nil {
		if sectionStr, ok := conffilesSection.(string); ok {
			entry.Files = parseDpkgConffileInfo(strings.NewReader(sectionStr))
		}
	}

	if entry.Files == nil {
		// ensure the default value for a collection is never nil since this may be shown as JSON
		entry.Files = make([]pkg.DpkgFileRecord, 0)
	}

	return &entry, retErr
}

func splitPkgList(pkgList string) (ret []string) {
	fields := strings.Split(pkgList, ",")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			ret = append(ret, field)
		}
	}
	return ret
}

func extractAllFields(reader *bufio.Reader) (map[string]interface{}, error) {
	dpkgFields := make(map[string]interface{})
	var key string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
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
				log.Tracef("parsing dpkg status: extracting key-value from line: %s err: %v", line, err)
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
