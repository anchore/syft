package python

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/syft/pkg"
)

// parseWheelOrEggMetadata takes a Python Egg or Wheel (which share the same format and values for our purposes),
// returning all Python packages listed.
func parseWheelOrEggMetadata(_ string, reader io.Reader) (*pkg.EggWheelMetadata, error) {
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
				return nil, fmt.Errorf("no match for continuation: line: '%s'", line)
			}

			val, ok := fields[key]
			if !ok {
				return nil, fmt.Errorf("no previous key exists, expecting: %s", key)
			}
			// concatenate onto previous value
			val = fmt.Sprintf("%s\n %s", val, strings.TrimSpace(line))
			fields[key] = val
		default:
			// parse a new key (note, duplicate keys are overridden)
			if i := strings.Index(line, ":"); i > 0 {
				key = strings.TrimSpace(line[0:i])
				val := strings.TrimSpace(line[i+1:])

				fields[key] = val
			} else {
				return nil, fmt.Errorf("cannot parse field from line: '%s'", line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse python wheel/egg: %w", err)
	}

	var metadata pkg.EggWheelMetadata

	if err := mapstructure.Decode(fields, &metadata); err != nil {
		return nil, fmt.Errorf("unable to parse APK metadata: %w", err)
	}

	return &metadata, nil
}
