package php

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/binutils"
)

type interpreterCataloger struct {
	name                   string
	extensionsGlob         string
	interpreterClassifiers []binutils.Classifier
}

// NewInterpreterCataloger returns a new cataloger for PHP interpreters (php and php-fpm) as well as any installed C extensions.
func NewInterpreterCataloger() pkg.Cataloger { //nolint:funlen
	name := "php-interpreter-cataloger"
	m := binutils.ContextualEvidenceMatchers{CatalogerName: name}
	return interpreterCataloger{
		name: name,
		// example matches:
		// - as found in php-fpm docker library images: /usr/local/lib/php/extensions/no-debug-non-zts-20230831/bcmath.so
		// - as found in alpine images: /usr/lib/php83/modules/bcmath.so
		extensionsGlob: "**/php*/**/*.so",
		interpreterClassifiers: []binutils.Classifier{
			{
				Class:    "php-cli-binary",
				FileGlob: "**/php*",
				EvidenceMatcher: m.FileNameTemplateVersionMatcher(
					`(.*/|^)php[0-9]*$`,
					`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
				Package: "php-cli",
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeGeneric,
					Name: "php-cli",
					// the version will be filled in dynamically
				},
				CPEs: []cpe.CPE{
					{
						Attributes: cpe.Attributes{
							Part:    "a",
							Vendor:  "php",
							Product: "php",
						},
						Source: cpe.NVDDictionaryLookupSource,
					},
				},
			},
			{
				Class:    "php-fpm-binary",
				FileGlob: "**/php-fpm*",
				EvidenceMatcher: m.FileContentsVersionMatcher(
					`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
				Package: "php-fpm",
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeGeneric,
					Name: "php-fpm",
					// the version will be filled in dynamically
				},
				CPEs: []cpe.CPE{
					{
						Attributes: cpe.Attributes{
							Part:    "a",
							Vendor:  "php",
							Product: "php",
						},
						Source: cpe.NVDDictionaryLookupSource,
					},
				},
			},
			{
				Class:    "php-apache-binary",
				FileGlob: "**/apache*/**/libphp*.so",
				EvidenceMatcher: m.FileContentsVersionMatcher(
					`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
				Package: "libphp",
				PURL: packageurl.PackageURL{
					Type: packageurl.TypeGeneric,
					Name: "php",
					// the version will be filled in dynamically
				},
				CPEs: []cpe.CPE{
					{
						Attributes: cpe.Attributes{
							Part:    "a",
							Vendor:  "php",
							Product: "php",
						},
						Source: cpe.NVDDictionaryLookupSource,
					},
				},
			},
		},
	}
}

func (p interpreterCataloger) Name() string {
	return p.name
}

func (p interpreterCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	interpreterPkgs, intErrs := p.catalogInterpreters(resolver)
	extensionPkgs, extErrs := p.catalogExtensions(resolver)

	// TODO: a future iteration of this cataloger could be to read all php.ini / php/conf.d/*.ini files and indicate which extensions are enabled
	// and attempt to resolve the extension_dir. This can be tricky as it is a #define in the php source code and not always available
	// in configuration. For the meantime we report all extensions present

	// create a relationship for each interpreter package to the extensions
	var relationships []artifact.Relationship
	for _, interpreter := range interpreterPkgs {
		for _, extension := range extensionPkgs {
			relationships = append(relationships, artifact.Relationship{
				From: extension,
				To:   interpreter,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	var allPkgs []pkg.Package
	allPkgs = append(allPkgs, interpreterPkgs...)
	allPkgs = append(allPkgs, extensionPkgs...)

	return allPkgs, relationships, unknown.Join(intErrs, extErrs)
}

func (p interpreterCataloger) catalogInterpreters(resolver file.Resolver) ([]pkg.Package, error) {
	var errs error
	var packages []pkg.Package
	for _, cls := range p.interpreterClassifiers {
		locations, err := resolver.FilesByGlob(cls.FileGlob)
		if err != nil {
			// convert any file.Resolver path errors to unknowns with locations
			errs = unknown.Join(errs, unknown.ProcessPathErrors(err))
			continue
		}
		for _, location := range locations {
			pkgs, err := cls.EvidenceMatcher(cls, binutils.MatcherContext{Resolver: resolver, Location: location})
			if err != nil {
				errs = unknown.Append(errs, location, err)
				continue
			}
			packages = append(packages, pkgs...)
		}
	}
	return packages, errs
}

func (p interpreterCataloger) catalogExtensions(resolver file.Resolver) ([]pkg.Package, error) {
	locations, err := resolver.FilesByGlob(p.extensionsGlob)
	if err != nil {
		// convert any file.Resolver path errors to unknowns with locations
		return nil, unknown.ProcessPathErrors(err)
	}

	var packages []pkg.Package
	var errs error
	for _, location := range locations {
		pkgs, err := p.catalogExtension(resolver, location)
		if err != nil {
			errs = unknown.Append(errs, location, err)
			continue
		}
		packages = append(packages, pkgs...)
	}
	return packages, errs
}

func (p interpreterCataloger) catalogExtension(resolver file.Resolver, location file.Location) ([]pkg.Package, error) {
	reader, err := resolver.FileContentsByLocation(location)
	defer internal.CloseAndLogError(reader, location.RealPath)
	if err != nil {
		return nil, unknown.ProcessPathErrors(err)
	}

	name, cls := p.getClassifier(location.RealPath)
	if name == "" || cls == nil {
		return nil, nil
	}

	pkgs, err := cls.EvidenceMatcher(*cls, binutils.MatcherContext{Resolver: resolver, Location: location})
	if err != nil {
		return nil, unknown.New(location, err)
	}

	return pkgs, err
}

func (p interpreterCataloger) getClassifier(realPath string) (string, *binutils.Classifier) {
	if !strings.HasSuffix(realPath, ".so") {
		return "", nil
	}

	base := path.Base(realPath)
	name := strings.TrimSuffix(base, ".so")

	var match string
	switch name {
	case "mysqli":
		match = `(mysqlnd|mysqli)?\s*\x00*(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+API`
	case "opcache":
		match = `(?m)\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+`
	case "zip":
		match = `\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+Zip`
	default:
		match = fmt.Sprintf(`(?m)(\x00+%s)?\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+API`, name)
	}

	return name, &binutils.Classifier{
		Class:           fmt.Sprintf("php-ext-%s-binary", name),
		EvidenceMatcher: binutils.FileContentsVersionMatcher(p.name, match),
		Package:         name,
		PURL: packageurl.PackageURL{
			Type: packageurl.TypeGeneric,
			Name: name,
			// the version will be filled in dynamically
		},
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
