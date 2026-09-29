package debian

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// maxDpkgFileRecords bounds the file lists parsed out of md5sums and conffiles. A byte cap on the
// enclosing stream is not enough on its own: the shortest line that still yields a record is 4 bytes,
// so 16MB of control.tar buys millions of records.
//
// The number comes from measuring what a record actually retains, not from the struct size. A
// DpkgFileRecord is 32 bytes, but a populated one also heap-allocates a file.Digest and three string
// backing arrays: 121 bytes each with realistic Debian paths, 70 with minimal ones. At this bound that
// is ~24MB per package, and the effective ceiling is that times cataloger parallelism (NumCPU*4).
// The largest real Debian packages ship on the order of 10^4 files, so this leaves ~5x headroom.
const maxDpkgFileRecords = 200_000

// parseDpkgMD5Info returns the records it managed to parse, plus a non-nil error when the record bound
// was hit (wrapping errClippedFileListing) or the scanner failed partway through.
func parseDpkgMD5Info(reader io.Reader) ([]pkg.DpkgFileRecord, error) {
	var findings []pkg.DpkgFileRecord
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		if len(findings) >= maxDpkgFileRecords {
			return findings, fmt.Errorf("%w: dpkg md5sums listing exceeds %d entries", errClippedFileListing, maxDpkgFileRecords)
		}
		line := scanner.Text()
		fields := strings.SplitN(line, " ", 2)
		if len(fields) == 2 {
			path := strings.TrimSpace(fields[1])
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			findings = append(findings, pkg.DpkgFileRecord{
				Path: path,
				Digest: &file.Digest{
					Algorithm: "md5",
					Value:     strings.TrimSpace(fields[0]),
				},
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("failed to scan dpkg md5sums: %w", err)
	}
	return findings, nil
}

// parseDpkgConffileInfo returns the records it managed to parse, plus a non-nil error when the record
// bound was hit (wrapping errClippedFileListing) or the scanner failed partway through.
func parseDpkgConffileInfo(reader io.Reader) ([]pkg.DpkgFileRecord, error) {
	var findings []pkg.DpkgFileRecord
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		if len(findings) >= maxDpkgFileRecords {
			return findings, fmt.Errorf("%w: dpkg conffiles listing exceeds %d entries", errClippedFileListing, maxDpkgFileRecords)
		}
		line := strings.Trim(scanner.Text(), " \n")
		fields := strings.SplitN(line, " ", 2)

		if line == "" {
			continue
		}

		var path string
		if len(fields) >= 1 {
			path = strings.TrimSpace(fields[0])
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
		}

		var digest *file.Digest
		if len(fields) >= 2 {
			digest = &file.Digest{
				Algorithm: "md5",
				Value:     strings.TrimSpace(fields[1]),
			}
		}

		if path != "" {
			record := pkg.DpkgFileRecord{
				Path:         path,
				IsConfigFile: true,
			}
			if digest != nil {
				record.Digest = digest
			}
			findings = append(findings, record)
		}
	}
	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("failed to scan dpkg conffiles: %w", err)
	}
	return findings, nil
}
