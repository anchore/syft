package golang

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

type goLicense struct {
	Value          string       `json:"val,omitempty"`
	SPDXExpression string       `json:"spdx,omitempty"`
	Type           license.Type `json:"type,omitempty"`
	URLs           []string     `json:"urls,omitempty"`
	Locations      []string     `json:"locations,omitempty"`
}

type goLicenseResolver struct {
	catalogerName         string
	opts                  CatalogerConfig
	localModCacheResolver file.Resolver
	licenseCache          cache.Resolver[[]goLicense]
	lowerLicenseFileNames *strset.Set
}

func newGoLicenseResolver(catalogerName string, opts CatalogerConfig) goLicenseResolver {
	var localModCacheResolver file.Resolver
	if opts.SearchLocalModCacheLicenses {
		localModCacheResolver = fileresolver.NewFromUnindexedDirectory(opts.LocalModCacheDir)
	}

	return goLicenseResolver{
		catalogerName:         catalogerName,
		opts:                  opts,
		localModCacheResolver: localModCacheResolver,
		licenseCache:          cache.GetResolverCachingErrors[[]goLicense]("golang"),
		lowerLicenseFileNames: strset.New(lowercaseLicenseFiles()...),
	}
}

func lowercaseLicenseFiles() []string {
	fileNames := licenses.FileNames()
	for i := range fileNames {
		fileNames[i] = strings.ToLower(fileNames[i])
	}
	return fileNames
}

func remotesForModule(proxies []string, noProxy []string, module string) []string {
	for _, pattern := range noProxy {
		if matched, err := path.Match(pattern, module); err == nil && matched {
			// matched to be direct for this module
			return directProxiesOnly
		}
	}

	return proxies
}

func (c *goLicenseResolver) getLicenses(resolver file.Resolver, moduleName, moduleVersion string) ([]pkg.License, error) {
	// search the scan target first, ignoring local and remote sources
	goLicenses, err := c.findLicenses(resolver,
		fmt.Sprintf(`**/go/pkg/mod/%s@%s/*`, processCaps(moduleName), moduleVersion),
	)
	if err != nil || len(goLicenses) > 0 {
		return toPkgLicenses(goLicenses), err
	}

	// look in the local host mod directory...
	if c.opts.SearchLocalModCacheLicenses {
		goLicenses, err = c.getLicensesFromLocal(moduleName, moduleVersion)
		if err != nil || len(goLicenses) > 0 {
			return toPkgLicenses(goLicenses), err
		}
	}

	// download from remote sources
	if c.opts.SearchRemoteLicenses {
		goLicenses, err = c.getLicensesFromRemote(moduleName, moduleVersion)
	}

	return toPkgLicenses(goLicenses), err
}

func (c *goLicenseResolver) getLicensesFromLocal(moduleName, moduleVersion string) ([]goLicense, error) {
	if c.localModCacheResolver == nil {
		return nil, nil
	}

	// if we're running against a directory on the filesystem, it may not include the
	// user's homedir / GOPATH, so we defer to using the localModCacheResolver
	return c.findLicenses(c.localModCacheResolver, moduleSearchGlob(moduleName, moduleVersion))
}

func (c *goLicenseResolver) getLicensesFromRemote(moduleName, moduleVersion string) ([]goLicense, error) {
	return c.licenseCache.Resolve(fmt.Sprintf("%s/%s", moduleName, moduleVersion), func() ([]goLicense, error) {
		proxies := remotesForModule(c.opts.Proxies, c.opts.NoProxy, moduleName)

		fsys, err := getModule(proxies, moduleName, moduleVersion)
		if err != nil {
			return nil, err
		}

		var out []goLicense
		err = fs.WalkDir(fsys, ".", func(filePath string, d fs.DirEntry, _ error) error {
			if !c.lowerLicenseFileNames.Has(strings.ToLower(d.Name())) {
				return nil
			}
			rdr, err := fsys.Open(filePath)
			if err != nil {
				log.Debugf("error opening license file %s: %v", filePath, err)
				return nil
			}
			parsed, err := licenses.Parse(rdr, file.NewLocation(path.Join(moduleDir(moduleName, moduleVersion), filePath)))
			if err != nil {
				log.Debugf("error parsing license file %s: %v", filePath, err)
				return nil
			}
			out = append(out, toGoLicenses(parsed)...)
			return nil
		})
		return out, err
	})
}

func (c *goLicenseResolver) findLicenses(resolver file.Resolver, globMatch string) ([]goLicense, error) {
	var out []goLicense
	locations, err := resolver.FilesByGlob(globMatch)
	if err != nil {
		return nil, err
	}

	for _, l := range locations {
		parsed, err := c.parseLicenseFromLocation(l, resolver)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed...)
	}

	// if we have a directory but simply don't have any found license files, indicate this so we
	// don't re-download modules continually
	if len(locations) > 0 && len(out) == 0 {
		return nil, noLicensesFound{
			glob: globMatch,
		}
	}

	return out, nil
}

func (c *goLicenseResolver) parseLicenseFromLocation(l file.Location, resolver file.Resolver) ([]goLicense, error) {
	var out []goLicense
	fileName := path.Base(l.RealPath)
	if c.lowerLicenseFileNames.Has(strings.ToLower(fileName)) {
		contents, err := resolver.FileContentsByLocation(l)
		if err != nil {
			return nil, err
		}
		defer internal.CloseAndLogError(contents, l.RealPath)
		parsed, err := licenses.Parse(contents, l)
		if err != nil {
			return nil, err
		}

		out = append(out, toGoLicenses(parsed)...)
	}
	return out, nil
}

func moduleDir(moduleName, moduleVersion string) string {
	return fmt.Sprintf("%s@%s", processCaps(moduleName), moduleVersion)
}

func moduleSearchGlob(moduleName, moduleVersion string) string {
	return fmt.Sprintf("%s/*", moduleDir(moduleName, moduleVersion))
}

func requireCollection[T any](licenses []T) []T {
	if licenses == nil {
		return make([]T, 0)
	}
	return licenses
}

var capReplacer = regexp.MustCompile("[A-Z]")

func processCaps(s string) string {
	return capReplacer.ReplaceAllStringFunc(s, func(s string) string {
		return "!" + strings.ToLower(s)
	})
}

func getModule(proxies []string, moduleName, moduleVersion string) (fsys fs.FS, err error) {
	for _, proxy := range proxies {
		u, _ := url.Parse(proxy)
		if proxy == "direct" {
			fsys, err = getModuleRepository(moduleName, moduleVersion)
			continue
		}
		switch u.Scheme {
		case "https", "http":
			fsys, err = getModuleProxy(proxy, moduleName, moduleVersion)
		case "file":
			p := filepath.Join(u.Path, moduleName, "@v", moduleVersion)
			fsys = os.DirFS(p)
		}
		if fsys != nil {
			break
		}
	}
	return
}

func getModuleProxy(proxy string, moduleName string, moduleVersion string) (out fs.FS, _ error) {
	u := fmt.Sprintf("%s/%s/@v/%s.zip", proxy, moduleName, moduleVersion)

	// get the module zip
	resp, err := http.Get(u) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		u = fmt.Sprintf("%s/%s/@v/%s.zip", proxy, strings.ToLower(moduleName), moduleVersion)

		// try lowercasing it; some packages have mixed casing that really messes up the proxy
		resp, err = http.Get(u) //nolint:gosec
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get module zip: %s", resp.Status)
		}
	}

	// read the zip
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	out, err = zip.NewReader(bytes.NewReader(b), resp.ContentLength)
	versionPath := findVersionPath(out, ".")
	out = getSubFS(out, versionPath)

	return out, err
}

func findVersionPath(f fs.FS, dir string) string {
	list, _ := fs.ReadDir(f, dir)

	for _, entry := range list {
		name := entry.Name()
		if strings.Contains(name, "@") {
			return name
		}
		found := findVersionPath(f, path.Join(dir, name))
		if found != "" {
			return path.Join(name, found)
		}
	}

	return ""
}

func getModuleRepository(moduleName string, moduleVersion string) (fs.FS, error) {
	repoName := moduleName
	parts := strings.Split(moduleName, "/")
	if len(parts) > 2 {
		repoName = fmt.Sprintf("%s/%s/%s", parts[0], parts[1], parts[2])
	}

	f := memfs.New()
	buf := &bytes.Buffer{}
	_, err := git.Clone(memory.NewStorage(), f, &git.CloneOptions{
		URL:           fmt.Sprintf("https://%s", repoName),
		ReferenceName: plumbing.NewTagReferenceName(moduleVersion), // FIXME version might be a SHA
		SingleBranch:  true,
		Depth:         1,
		Progress:      buf,
	})

	if err != nil {
		return nil, fmt.Errorf("%w -- %s", err, buf.String())
	}

	return billyFSAdapter{fs: f}, nil
}

type noLicensesFound struct {
	glob string
}

func (l noLicensesFound) Error() string {
	return fmt.Sprintf("unable to find license information matching: %s", l.glob)
}

var _ error = (*noLicensesFound)(nil)

func toPkgLicenses(goLicenses []goLicense) []pkg.License {
	var out []pkg.License
	for _, l := range goLicenses {
		out = append(out, pkg.License{
			Value:          l.Value,
			SPDXExpression: l.SPDXExpression,
			Type:           l.Type,
			URLs:           l.URLs,
			Locations:      toPkgLocations(l.Locations),
		})
	}
	return requireCollection(out)
}

func toPkgLocations(goLocations []string) file.LocationSet {
	out := file.NewLocationSet()
	for _, l := range goLocations {
		out.Add(file.NewLocation(l))
	}
	return out
}

func toGoLicenses(pkgLicenses []pkg.License) []goLicense {
	var out []goLicense
	for _, l := range pkgLicenses {
		out = append(out, goLicense{
			Value:          l.Value,
			SPDXExpression: l.SPDXExpression,
			Type:           l.Type,
			URLs:           l.URLs,
			Locations:      toGoLocations(l.Locations),
		})
	}
	return out
}

func toGoLocations(locations file.LocationSet) []string {
	var out []string
	for _, l := range locations.ToSlice() {
		out = append(out, l.RealPath)
	}
	return out
}
