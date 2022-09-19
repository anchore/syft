package python

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
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

func parseInstalledFiles(reader io.Reader, location, sitePackagesRootPath string) ([]pkg.PythonFileRecord, error) {
	var installedFiles []pkg.PythonFileRecord
	r := bufio.NewReader(reader)

	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("unable to read python installed-files file: %w", err)
		}

		if location != "" && sitePackagesRootPath != "" {
			joinedPath := filepath.Join(filepath.Dir(location), line)
			line, err = filepath.Rel(sitePackagesRootPath, joinedPath)
			if err != nil {
				return nil, err
			}
		}

		installedFile := pkg.PythonFileRecord{
			Path: strings.ReplaceAll(line, "\n", ""),
		}

		installedFiles = append(installedFiles, installedFile)
	}

	return installedFiles, nil
}
