package golang

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

type goLicenses struct {
	searchLocalModCacheLicenses bool
	localModCacheResolver       source.FileResolver
}

func newGoLicenses(opts GoCatalogerOpts) goLicenses {
	return goLicenses{
		searchLocalModCacheLicenses: opts.SearchLocalModCacheLicenses,
		localModCacheResolver:       modCacheResolver(opts.LocalModCacheDir),
	}
}

func defaultGoPath() string {
	goPath := os.Getenv("GOPATH")

	if goPath == "" {
		homeDir, err := homedir.Dir()
		if err != nil {
			log.Debug("unable to determine user home dir: %v", err)
		} else {
			goPath = path.Join(homeDir, "go")
		}
	}

	return goPath
}

// resolver needs to be shared between mod file & binary scanners so it's only scanned once
var modCacheResolvers = map[string]source.FileResolver{}

func modCacheResolver(modCacheDir string) source.FileResolver {
	if modCacheDir == "" {
		goPath := defaultGoPath()
		if goPath != "" {
			modCacheDir = path.Join(goPath, "pkg", "mod")
		}
	}

	if r, ok := modCacheResolvers[modCacheDir]; ok {
		return r
	}

	var r source.FileResolver

	if modCacheDir == "" {
		log.Trace("unable to determine mod cache directory, skipping mod cache resolver")
		r = source.NewMockResolverForPaths()
	} else {
		stat, err := os.Stat(modCacheDir)

		if os.IsNotExist(err) || stat == nil || !stat.IsDir() {
			log.Tracef("unable to open mod cache directory: %s, skipping mod cache resolver", modCacheDir)
			r = source.NewMockResolverForPaths()
		} else {
			r = source.NewDeferredResolverFromSource(func() (source.Source, error) {
				return source.NewFromDirectory(modCacheDir)
			})
		}
	}

	modCacheResolvers[modCacheDir] = r

	return r
}

func (c *goLicenses) getLicenses(resolver source.FileResolver, moduleName, moduleVersion string) (licenses []string, err error) {
	moduleName = processCaps(moduleName)

	licenses, err = findLicenses(resolver,
		fmt.Sprintf(`**/go/pkg/mod/%s@%s/*`, moduleName, moduleVersion),
	)

	if c.searchLocalModCacheLicenses && err == nil && len(licenses) == 0 {
		// if we're running against a directory on the filesystem, it may not include the
		// user's homedir / GOPATH, so we defer to using the localModCacheResolver
		licenses, err = findLicenses(c.localModCacheResolver,
			fmt.Sprintf(`**/%s@%s/*`, moduleName, moduleVersion),
		)
	}

	// always return a non-nil slice
	if licenses == nil {
		licenses = []string{}
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

			out = append(out, parsed...)
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
