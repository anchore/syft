package python

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/syft/pkg"
)

// parseWheelOrEggMetadata takes a Python Egg or Wheel (which share the same format and values for our purposes),
// returning all Python packages listed.
func parseWheelOrEggMetadata(path file.Path, reader io.Reader) (pkg.PythonPackageMetadata, error) {
	fields := make(map[string]string)
	var key string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\n")

		// empty line indicates end of entry
		if len(line) == 0 {
			// if the entry has not started, keep parsing lines
			if len(fields) == 0 {
				continue
			}
			break
		}

		switch {
		case strings.HasPrefix(line, " "):
			// a field-body continuation
			if len(key) == 0 {
				return pkg.PythonPackageMetadata{}, fmt.Errorf("no match for continuation: line: '%s'", line)
			}

			val, ok := fields[key]
			if !ok {
				return pkg.PythonPackageMetadata{}, fmt.Errorf("no previous key exists, expecting: %s", key)
			}
			// concatenate onto previous value
			val = fmt.Sprintf("%s\n %s", val, strings.TrimSpace(line))
			fields[key] = val
		default:
			// parse a new key (note, duplicate keys are overridden)
			if i := strings.Index(line, ":"); i > 0 {
				// mapstruct cannot map keys with dashes, and we are expected to persist the "Author-email" field
				key = strings.ReplaceAll(strings.TrimSpace(line[0:i]), "-", "")
				val := strings.TrimSpace(line[i+1:])

				fields[key] = val
			} else {
				return pkg.PythonPackageMetadata{}, fmt.Errorf("cannot parse field from line: '%s'", line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return pkg.PythonPackageMetadata{}, fmt.Errorf("failed to parse python wheel/egg: %w", err)
	}

	var metadata pkg.PythonPackageMetadata
	if err := mapstructure.Decode(fields, &metadata); err != nil {
		return pkg.PythonPackageMetadata{}, fmt.Errorf("unable to parse APK metadata: %w", err)
	}

	// add additional metadata not stored in the egg/wheel metadata file

	sitePackagesRoot := filepath.Clean(filepath.Join(filepath.Dir(string(path)), ".."))
	metadata.SitePackagesRootPath = sitePackagesRoot

	return metadata, nil
}
