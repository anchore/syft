package python

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/mitchellh/mapstructure"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type parsedData struct {
	Licenses          string `mapstructure:"License"`
	LicenseLocation   file.Location
	pkg.PythonPackage `mapstructure:",squash"`
}

// parseWheelOrEggMetadata takes a Python Egg or Wheel (which share the same format and values for our purposes),
// returning all Python packages listed.
func parseWheelOrEggMetadata(path string, reader io.Reader) (parsedData, error) {
	fields := make(map[string]string)
	var key string

	scanner := bufio.NewScanner(reader)
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
				return parsedData{}, err
			}

			fields[key] = updatedValue
		default:
			// parse a new key (note, duplicate keys are overridden)
			if i := strings.Index(line, ":"); i > 0 {
				// mapstruct cannot map keys with dashes, and we are expected to persist the "Author-email" field
				key = strings.ReplaceAll(strings.TrimSpace(line[0:i]), "-", "")
				val := strings.TrimSpace(line[i+1:])

				fields[key] = val
			} else {
				log.Warnf("cannot parse field from path: %q from line: %q", path, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return parsedData{}, fmt.Errorf("failed to parse python wheel/egg: %w", err)
	}

	var pd parsedData
	if err := mapstructure.Decode(fields, &pd); err != nil {
		return pd, fmt.Errorf("unable to parse APK metadata: %w", err)
	}

	// add additional metadata not stored in the egg/wheel metadata file

	pd.SitePackagesRootPath = determineSitePackagesRootPath(path)
	if pd.Licenses != "" {
		pd.LicenseLocation = file.NewLocation(path)
	}

	return pd, nil
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
func handleFieldBodyContinuation(key, line string, fields map[string]string) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("no match for continuation: line: '%s'", line)
	}

	val, ok := fields[key]
	if !ok {
		return "", fmt.Errorf("no previous key exists, expecting: %s", key)
	}

	// concatenate onto previous value
	return fmt.Sprintf("%s\n %s", val, strings.TrimSpace(line)), nil
}
