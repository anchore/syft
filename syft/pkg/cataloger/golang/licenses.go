package golang

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

type goLicenses struct {
	searchLocalGoModForLicenses bool
	localGoModResolver          source.FileResolver
}

func newGoLicenses(searchLocalGoModForLicenses bool) goLicenses {
	return goLicenses{
		searchLocalGoModForLicenses: searchLocalGoModForLicenses,
		localGoModResolver:          deferredResolver,
	}
}

// this needs to be shared between GoMod & GoBinary so it's only scanned once
var deferredResolver = deferredResolverForLocalGoMod()

func deferredResolverForLocalGoMod() source.FileResolver {
	return source.NewDeferredResolverFromSource(func() (source.Source, error) {
		goPath := os.Getenv("GOPATH")

		if goPath == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				log.Debug("unable to determine user home dir: %v", err)
			}
			goPath = path.Join(homeDir, "go")
		}

		return source.NewFromDirectory(path.Join(goPath, "pkg", "mod"))
	})
}

func (c *goLicenses) getLicenses(resolver source.FileResolver, moduleName, moduleVersion string) (licenses []string, err error) {
	nameParts := strings.Split(moduleName, "/")

	if len(nameParts) < 3 {
		return nil, fmt.Errorf("unexpected go package name: %s", moduleName)
	}

	host := processCaps(nameParts[0])
	org := processCaps(nameParts[1])
	repo := processCaps(nameParts[2])

	licenses, err = findLicenses(resolver,
		fmt.Sprintf(`**/go/pkg/mod/%s/%s/%s@%s/*`, host, org, repo, moduleVersion),
	)
	if err != nil {
		return nil, err
	}

	if len(licenses) == 0 && c.searchLocalGoModForLicenses {
		// if we're running against a directory on the filesystem, it may not include the
		// user's homedir / GOPATH, so we defer to using the localGoModResolver
		licenses, err = findLicenses(c.localGoModResolver,
			fmt.Sprintf(`**/%s/%s/%s@%s/*`, host, org, repo, moduleVersion),
		)
	}

	return
}

func findLicenses(resolver source.FileResolver, globMatch string) (out []string, err error) {
	if resolver == nil {
		return
	}

	locations, err := resolver.FilesByGlob(globMatch)
	if err != nil {
		return nil, err
	}

	for _, l := range locations {
		fileName := path.Base(l.RealPath)
		if licenses.FileNameSet.Contains(fileName) {
			contents, err := resolver.FileContentsByLocation(l)
			if err != nil {
				return nil, err
			}
			parsed, err := licenses.Parse(contents)
			if err != nil {
				return nil, err
			}

			if parsed != nil {
				out = append(out, parsed...)
			}
		}
	}

	return
}

var capReplacer = regexp.MustCompile("[A-Z]")

func processCaps(s string) string {
	return capReplacer.ReplaceAllStringFunc(s, func(s string) string {
		return "!" + strings.ToLower(s)
	})
}
