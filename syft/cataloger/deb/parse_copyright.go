package deb

import (
	"bufio"
	"io"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
)

// For more information see: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-syntax

func parseLicensesFromCopyright(reader io.Reader) []string {
	findings := internal.NewStringSet()
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "License:") {
			candidate := strings.Replace(line, "License:", "", 1)
			candidate = strings.TrimSpace(candidate)
			if strings.Contains(candidate, " or ") || strings.Contains(candidate, " and ") {
				// this is a multi-license summary, ignore this as other recurrent license lines should cover this
				continue
			}
			if candidate != "" && strings.ToLower(candidate) != "none" {
				findings.Add(candidate)
			}
		}
	}

	results := findings.ToSlice()

	sort.Strings(results)

	return results
}
