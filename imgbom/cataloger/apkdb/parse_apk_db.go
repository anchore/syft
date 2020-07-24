package apkdb

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/imgbom/imgbom/pkg"
)

func parseApkDB(_ string, reader io.Reader) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)

	scanner := bufio.NewScanner(reader)
	onDoubleLF := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		for i := 0; i < len(data); i++ {
			if i > 0 && data[i-1] == '\n' && data[i] == '\n' {
				return i + 1, data[:i-1], nil
			}
		}
		if !atEOF {
			return 0, nil, nil
		}
		// deliver the last token (which could be an empty string)
		return 0, data, bufio.ErrFinalToken
	}

	scanner.Split(onDoubleLF)
	for scanner.Scan() {
		metadata, err := parseApkDBEntry(strings.NewReader(scanner.Text()))
		if err != nil {
			return nil, err
		}
		if metadata != nil {
			packages = append(packages, pkg.Package{
				Name:     metadata.Package,
				Version:  metadata.Version,
				Licenses: strings.Split(metadata.License, " "),
				Type:     pkg.ApkPkg,
				Metadata: *metadata,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse APK DB file: %w", err)
	}

	return packages, nil
}

func parseApkDBEntry(reader io.Reader) (*pkg.ApkMetadata, error) {
	var entry pkg.ApkMetadata
	pkgFields := make(map[string]interface{})
	files := make([]string, 0)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}

		key := fields[0]
		value := strings.TrimSpace(fields[1])

		switch key {
		case "F":
			// extract all file entries, don't store in map
			files = append(files, value)
			continue
		case "I", "S":
			// coerce to integer
			iVal, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse APK int: '%+v'", value)
			}
			pkgFields[key] = iVal
		default:
			pkgFields[key] = value
		}
	}

	if err := mapstructure.Decode(pkgFields, &entry); err != nil {
		return nil, fmt.Errorf("unable to parse APK metadata: %w", err)
	}
	if entry.Package == "" {
		return nil, nil
	}

	entry.Files = files

	return &entry, nil
}
