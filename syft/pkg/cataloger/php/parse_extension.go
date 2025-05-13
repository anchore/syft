package php

import (
	"context"
	"fmt"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"path"
	"strings"
)

func parseExtension(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	name, cls := getClassifier(reader.Location.RealPath)
	if name == "" || cls == nil {
		return nil, nil, nil
	}

	pkgs, err := cls.EvidenceMatcher(*cls, binary.MatcherContext{Resolver: resolver, Location: reader.Location})
	if err != nil {
		return nil, nil, unknown.New(reader.Location, err)
	}

	return pkgs, nil, err
}

func getClassifier(p string) (string, *binary.Classifier) {
	if !strings.HasSuffix(p, ".so") {
		return "", nil
	}

	base := path.Base(p)
	name := strings.TrimSuffix(base, ".so")

	var match string
	switch name {
	// TODO: case "dom:"
	case "mysqli":
		match = `mysqlnd (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00{2}`
	case "opcache":
		match = `overflow\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00{2}Zend`
	case "zip":
		match = `\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00{2}Zip`
	default:
		match = fmt.Sprintf(`(?m)(\x00+%s)?\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00{2}API`, name)
	}

	purlStr := fmt.Sprintf("pkg:generic/%s@version", name)
	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		log.WithFields("error", err, "purl", purlStr).Trace("invalid PURL for php extension")
	}

	return name, &binary.Classifier{
		Class:           fmt.Sprintf("php-ext-%s-binary", name),
		FileGlob:        fmt.Sprintf("**/%s.so", name),
		EvidenceMatcher: binary.FileContentsVersionMatcher(match),
		Package:         name,
		PURL:            purl,
		CPEs: []cpe.CPE{
			{
				Attributes: cpe.Attributes{
					Part:    "a",
					Vendor:  fmt.Sprintf("php-%s", name),
					Product: fmt.Sprintf("php-%s", name),
				},
				Source: cpe.GeneratedSource,
			},
		},
	}
}
