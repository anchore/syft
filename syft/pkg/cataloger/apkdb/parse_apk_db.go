package apkdb

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

// integrity check
var _ generic.Parser = parseApkDB

// parseApkDb parses individual packages from a given Alpine DB file. For more information on specific fields
// see https://wiki.alpinelinux.org/wiki/Apk_spec .
func parseApkDB(_ source.FileResolver, env *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// larger capacity for the scanner.
	const maxScannerCapacity = 1024 * 1024
	// a new larger buffer for the scanner
	bufScan := make([]byte, maxScannerCapacity)
	pkgs := make([]pkg.Package, 0)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(bufScan, maxScannerCapacity)
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

	var r *linux.Release
	if env != nil {
		r = env.LinuxRelease
	}

	scanner.Split(onDoubleLF)
	for scanner.Scan() {
		metadata, err := parseApkDBEntry(strings.NewReader(scanner.Text()))
		if err != nil {
			return nil, nil, err
		}
		if metadata != nil {
			pkgs = append(pkgs, newPackage(*metadata, r, reader.Location))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse APK DB file: %w", err)
	}

	return pkgs, nil, nil
}

// parseApkDBEntry reads and parses a single pkg.ApkMetadata element from the stream, returning nil if their are no more entries.
//
//nolint:funlen
func parseApkDBEntry(reader io.Reader) (*pkg.ApkMetadata, error) {
	var entry pkg.ApkMetadata
	pkgFields := make(map[string]interface{})
	files := make([]pkg.ApkFileRecord, 0)

	var fileRecord *pkg.ApkFileRecord
	lastFile := "/"

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
			currentFile := "/" + value

			newFileRecord := pkg.ApkFileRecord{
				Path: currentFile,
			}
			files = append(files, newFileRecord)
			fileRecord = &files[len(files)-1]

			// future aux references are relative to previous "F" records
			lastFile = currentFile
			continue
		case "R":
			newFileRecord := pkg.ApkFileRecord{
				Path: path.Join(lastFile, value),
			}
			files = append(files, newFileRecord)
			fileRecord = &files[len(files)-1]
		case "a", "M":
			ownershipFields := strings.Split(value, ":")
			if len(ownershipFields) < 3 {
				log.Warnf("unexpected APK ownership field: %q", value)
				continue
			}
			if fileRecord == nil {
				log.Warnf("ownership field with no parent record: %q", value)
				continue
			}
			fileRecord.OwnerUID = ownershipFields[0]
			fileRecord.OwnerGID = ownershipFields[1]
			fileRecord.Permissions = ownershipFields[2]
			// note: there are more optional fields available that we are not capturing, e.g.:
			// "0:0:755:Q1JaDEHQHBbizhEzoWK1YxuraNU/4="
		case "Z":
			if fileRecord == nil {
				log.Warnf("checksum field with no parent record: %q", value)
				continue
			}
			fileRecord.Digest = processChecksum(value)
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

func processChecksum(value string) *file.Digest {
	// from: https://wiki.alpinelinux.org/wiki/Apk_spec
	// The package checksum field is the SHA1 hash of the second gzip stream (control stream) in the package. The
	// binary hash digest is base64 encoded. This is prefixed with Q1 to differentiate it from the MD5 hashes
	// used in older index formats. It is not possible to compute this checksum with standard command line tools
	// but the apk-tools can compute it in their index operation.

	// based on https://github.com/alpinelinux/apk-tools/blob/dd1908f2fc20b4cfe2c15c55fafaa5fadfb599dc/src/blob.c#L379-L393
	// it seems that the old md5 checksum value was only the hex representation (not base64)
	algorithm := "md5"
	if strings.HasPrefix(value, "Q1") {
		algorithm = "'Q1'+base64(sha1)"
	}

	return &file.Digest{
		Algorithm: algorithm,
		Value:     value,
	}
}
