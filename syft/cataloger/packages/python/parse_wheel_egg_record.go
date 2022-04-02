package python

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// parseWheelOrEggMetadata takes a Python Egg or Wheel (which share the same format and values for our purposes),
// returning all Python packages listed.
func parseWheelOrEggRecord(reader io.Reader) ([]pkg.PythonFileRecord, error) {
	var records []pkg.PythonFileRecord
	r := csv.NewReader(reader)

	for {
		recordList, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("unable to read python record file: %w", err)
		}

		if len(recordList) != 3 {
			return nil, fmt.Errorf("python record an unexpected length=%d: %q", len(recordList), recordList)
		}

		var record pkg.PythonFileRecord

		for idx, item := range recordList {
			switch idx {
			case 0:
				record.Path = item
			case 1:
				if item == "" {
					continue
				}
				fields := strings.SplitN(item, "=", 2)
				if len(fields) != 2 {
					log.Warnf("unexpected python record digest: %q", item)
					continue
				}

				record.Digest = &pkg.PythonFileDigest{
					Algorithm: fields[0],
					Value:     fields[1],
				}
			case 2:
				record.Size = item
			}
		}

		records = append(records, record)
	}

	return records, nil
}
