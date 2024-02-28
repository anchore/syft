package debian

import (
	"bufio"
	"io"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func parseDpkgMD5Info(reader io.Reader) (findings []pkg.DpkgFileRecord) {
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
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
	return findings
}

func parseDpkgConffileInfo(reader io.Reader) (findings []pkg.DpkgFileRecord) {
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
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
	return findings
}
