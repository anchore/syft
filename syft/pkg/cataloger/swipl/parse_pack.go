package swipl

import (
	"context"
	"io"
	"regexp"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func parsePackPackage(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	nameRe := regexp.MustCompile(`name\(\s*'?([^')]+)'?\s*\)`)
	versionRe := regexp.MustCompile(`version\('([^']+)'\)`)
	homeRe := regexp.MustCompile(`home\(\s*'([^']+)'\s*\)`)
	authorRe := regexp.MustCompile(`(author|packager)\(\s*'([^']+)'\s*(?:,\s*'([^']+)'\s*)?\)`)

	data, err := io.ReadAll(reader)
	if err != nil {
		log.WithFields("error", err).Trace("unable to parse Rockspec app")
		return nil, nil, nil
	}

	name := nameRe.FindSubmatch(data)
	version := versionRe.FindSubmatch(data)

	if name == nil || version == nil {
		log.Debugf("encountered pack.pl file without a name and/or version field, ignoring (path=%q)", reader.Path())
		return nil, nil, nil
	}

	entry := pkg.SwiplPackEntry{
		Name:    string(name[1]),
		Version: string(version[1]),
	}

	home := homeRe.FindSubmatch(data)

	if home != nil {
		entry.Homepage = string(home[1])
	}

	authors := authorRe.FindAllSubmatch(data, -1)

	for _, a := range authors {
		switch string(a[1]) {
		case "author":
			entry.Author = string(a[2])
			entry.AuthorEmail = string(a[3])
		case "packager":
			entry.Packager = string(a[2])
			entry.PackagerEmail = string(a[3])
		}
	}

	pkgs = append(
		pkgs,
		newSwiplPackPackage(
			entry,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	)

	return pkgs, nil, nil
}
