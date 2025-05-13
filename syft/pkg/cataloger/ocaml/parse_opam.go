package ocaml

import (
	"context"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

//nolint:funlen
func parseOpamPackage(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	opamVersionRe := regexp.MustCompile(`(?m)opam-version:\s*"[0-9]+\.[0-9]+"`)
	versionRe := regexp.MustCompile(`(?m)^version:\s*"(?P<version>[^"]*)"`)
	licenseRe := regexp.MustCompile(`(?m)^license:\s*(?P<license>(?:"[^"]*")|(?:\[[^\]]*\]))`)
	homepageRe := regexp.MustCompile(`(?m)homepage:\s*"(?P<url>[^"]+)"`)
	urlRe := regexp.MustCompile(`(?m)url\s*{(?P<url>[^}]+)}`)

	data, err := io.ReadAll(reader)
	if err != nil {
		log.WithFields("error", err).Trace("unable to read opam package")
		return nil, nil, nil
	}

	if opamVersionRe.FindSubmatch(data) == nil {
		log.WithFields("warning", err).Trace("opam version not found")
		return nil, nil, nil
	}

	// If name is inferred from file name/path
	var name, version string
	var licenses []string
	loc := reader.AccessPath
	dir, file := path.Split(loc)

	if file == "opam" {
		// folder name is the package name and version
		s := strings.SplitN(path.Base(dir), ".", 2)
		name = s[0]

		if len(s) > 1 {
			version = s[1]
		}
	} else {
		// filename is the package name and version is in the content
		name = strings.Replace(file, ".opam", "", 1)

		m := versionRe.FindSubmatch(data)

		if m != nil {
			version = string(m[1])
		}
	}

	entry := pkg.OpamPackage{
		Name:    name,
		Version: version,
	}

	licenseMatch := licenseRe.FindSubmatch(data)
	if licenseMatch != nil {
		licenses = parseLicenses(string(licenseMatch[1]))

		entry.Licenses = licenses
	}

	urlMatch := urlRe.FindSubmatch(data)
	if urlMatch != nil {
		url, checksums := parseURL(urlMatch[1])

		if url != "" {
			entry.URL = url
		}

		if checksums != nil {
			entry.Checksums = checksums
		}
	}

	homepageMatch := homepageRe.FindSubmatch(data)
	if homepageMatch != nil {
		entry.Homepage = string(homepageMatch[1])
	}

	pkgs = append(
		pkgs,
		newOpamPackage(
			ctx,
			entry,
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	)

	return pkgs, nil, nil
}

func parseLicenses(licensesStr string) []string {
	licenses := []string{}

	if licensesStr[:1] == `"` {
		content := licensesStr[1 : len(licensesStr)-1]
		licenses = append(licenses, content)
	} else {
		var d []string
		err := json.Unmarshal([]byte(licensesStr), &d)

		if err == nil {
			licenses = append(licenses, d...)
		}
	}

	return licenses
}

func parseURL(data []byte) (string, []string) {
	urlRe := regexp.MustCompile(`(?m)src:\s*"(?P<url>.*)"`)
	checksumsRe := regexp.MustCompile(`(?m)checksum:\s*("[^"]*"|\[\s*((?:"[^"]*"\s*)+)\])`)

	urlMatch := urlRe.FindSubmatch(data)
	if urlMatch == nil {
		return "", nil
	}

	url := urlMatch[1]

	var checksum []string
	checksumMatch := checksumsRe.FindSubmatch(data)
	if checksumMatch != nil {
		var fields []string
		if checksumMatch[2] != nil {
			fields = strings.Fields(string(checksumMatch[2]))
		} else {
			fields = strings.Fields(string(checksumMatch[1]))
		}

		for _, f := range fields {
			checksum = append(checksum, strings.ReplaceAll(f, `"`, ""))
		}
	}

	return string(url), checksum
}
