package deb

import (
	"bufio"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

func parseDpkgMD5Info(reader io.Reader) []pkg.DpkgFileRecord {
	// we must preallocate to ensure the resulting struct does not have null
	var findings = make([]pkg.DpkgFileRecord, 0)
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
				MD5:  strings.TrimSpace(fields[0]),
			})
		}
	}
	return findings
}
