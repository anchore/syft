package python

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type parsedData struct {
	// core info

	// DistInfoLocation is the location of the METADATA file within the .dist-info directory where we obtained the python package information
	DistInfoLocation  file.Location
	pkg.PythonPackage `mapstructure:",squash"`

	// license info

	Licenses          string `mapstructure:"License"`
	LicenseFile       string `mapstructure:"LicenseFile"`
	LicenseExpression string `mapstructure:"LicenseExpression"`
	LicenseFilePath   string
}

var pluralFields = map[string]bool{
	"ProvidesExtra": true,
	"RequiresDist":  true,
}

// parseWheelOrEggMetadata takes a Python Egg or Wheel (which share the same format and values for our purposes),
// returning all Python packages listed.
func parseWheelOrEggMetadata(locationReader file.LocationReadCloser) (parsedData, error) {
	fields, err := extractRFC5322Fields(locationReader)
	if err != nil {
		return parsedData{}, fmt.Errorf("unable to extract python wheel/egg metadata: %w", err)
	}

	var pd parsedData
	if err := mapstructure.Decode(fields, &pd); err != nil {
		return pd, fmt.Errorf("unable to translate python wheel/egg metadata: %w", err)
	}

	// add additional metadata not stored in the egg/wheel metadata file
	path := locationReader.Path()

	pd.SitePackagesRootPath = determineSitePackagesRootPath(path)
	if pd.Licenses != "" || pd.LicenseExpression != "" {
		pd.LicenseFilePath = path
	} else if pd.LicenseFile != "" {
		pd.LicenseFilePath = filepath.Join(filepath.Dir(path), pd.LicenseFile)
	}

	pd.DistInfoLocation = locationReader.Location

	return pd, nil
}

func extractRFC5322Fields(locationReader file.LocationReadCloser) (map[string]any, error) {
	fields := make(map[string]any)
	var key string

	// though this spec is governed by RFC 5322 (mail message), the metadata files are not guaranteed to be compliant.
	// We must survive parsing as much info as possible without failing and dropping the data.
	scanner := bufio.NewScanner(locationReader)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\n")

		// An empty line means we are done parsing (either because there's no more data,
		// or because a description follows as specified in
		// https://packaging.python.org/specifications/core-metadata/#description;
		// and at this time, we're not interested in the description).
		if len(line) == 0 {
			if len(fields) > 0 {
				break
			}

			// however, if the field parsing has not started yet, keep scanning lines
			continue
		}

		switch {
		case strings.HasPrefix(line, " "):
			// a field-body continuation
			updatedValue, err := handleFieldBodyContinuation(key, line, fields)
			if err != nil {
				return nil, err
			}

			fields[key] = updatedValue
		default:
			// parse a new key (note, duplicate keys that are for singular fields are overridden, where as plural fields are appended)
			if i := strings.Index(line, ":"); i > 0 {
				// mapstruct cannot map keys with dashes, and we are expected to persist the "Author-email" field
				key = strings.ReplaceAll(strings.TrimSpace(line[0:i]), "-", "")
				val := getFieldType(key, strings.TrimSpace(line[i+1:]))

				fields[key] = handleSingleOrMultiField(fields[key], val)
			} else {
				log.Debugf("cannot parse field from path: %q from line: %q", locationReader.Path(), line)
			}
		}
	}
	return fields, nil
}

func handleSingleOrMultiField(existingValue, val any) any {
	strSlice, ok := val.([]string)
	if !ok {
		return val
	}
	if existingValue == nil {
		return strSlice
	}

	switch existingValueTy := existingValue.(type) {
	case []string:
		return append(existingValueTy, strSlice...)
	case string:
		return append([]string{existingValueTy}, strSlice...)
	}

	return append([]string{fmt.Sprintf("%s", existingValue)}, strSlice...)
}

func getFieldType(key, in string) any {
	if plural, ok := pluralFields[key]; ok && plural {
		return []string{in}
	}
	return in
}

// isEggRegularFile determines if the specified path is the regular file variant
// of egg metadata (as opposed to a directory that contains more metadata
// files).
func isEggRegularFile(path string) bool {
	return intFile.GlobMatch(eggInfoGlob, path)
}

// determineSitePackagesRootPath returns the path of the site packages root,
// given the egg metadata file or directory specified in the path.
func determineSitePackagesRootPath(path string) string {
	if isEggRegularFile(path) {
		return filepath.Clean(filepath.Dir(path))
	}

	return filepath.Clean(filepath.Dir(filepath.Dir(path)))
}

// handleFieldBodyContinuation returns the updated value for the specified field after processing the specified line.
// If the continuation cannot be processed, it returns an error.
func handleFieldBodyContinuation(key, line string, fields map[string]any) (any, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("no match for continuation: line: '%s'", line)
	}

	val, ok := fields[key]
	if !ok {
		return "", fmt.Errorf("no previous key exists, expecting: %s", key)
	}

	// concatenate onto previous value
	switch s := val.(type) {
	case string:
		return fmt.Sprintf("%s\n %s", s, strings.TrimSpace(line)), nil
	case []string:
		if len(s) == 0 {
			s = append(s, "")
		}
		s[len(s)-1] = fmt.Sprintf("%s\n %s", s[len(s)-1], strings.TrimSpace(line))
		return s, nil
	default:
		return "", fmt.Errorf("unexpected type for continuation: %T", val)
	}
}
