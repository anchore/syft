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
	localModCacheDir      fs.FS
	licenseCache          cache.Resolver[[]goLicense]
	lowerLicenseFileNames *strset.Set
}

func newGoLicenseResolver(catalogerName string, opts CatalogerConfig) goLicenseResolver {
	var localModCacheDir fs.FS
	if opts.SearchLocalModCacheLicenses {
		localModCacheDir = os.DirFS(opts.LocalModCacheDir)
	}

	return goLicenseResolver{
		catalogerName:         catalogerName,
		opts:                  opts,
		localModCacheDir:      localModCacheDir,
		licenseCache:          cache.GetResolverCachingErrors[[]goLicense]("golang", "v1"),
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
	goLicenses, err := c.findLicensesInSource(resolver,
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
	if c.localModCacheDir == nil {
		return nil, nil
	}

	subdir := moduleDir(moduleName, moduleVersion)

	// get the local subdirectory containing the specific go module
	dir, err := fs.Sub(c.localModCacheDir, subdir)
	if err != nil {
		return nil, err
	}

	// if we're running against a directory on the filesystem, it may not include the
	// user's homedir / GOPATH, so we defer to using the localModCacheResolver
	// we use $GOPATH/pkg/mod to avoid leaking information about the user's system
	return c.findLicensesInFS("file://$GOPATH/pkg/mod/"+subdir+"/", dir)
}

func (c *goLicenseResolver) getLicensesFromRemote(moduleName, moduleVersion string) ([]goLicense, error) {
	return c.licenseCache.Resolve(fmt.Sprintf("%s/%s", moduleName, moduleVersion), func() ([]goLicense, error) {
		proxies := remotesForModule(c.opts.Proxies, c.opts.NoProxy, moduleName)

		urlPrefix, fsys, err := getModule(proxies, moduleName, moduleVersion)
		if err != nil {
			return nil, err
		}

		return c.findLicensesInFS(urlPrefix, fsys)
	})
}

func (c *goLicenseResolver) findLicensesInFS(urlPrefix string, fsys fs.FS) ([]goLicense, error) {
	var out []goLicense
	err := fs.WalkDir(fsys, ".", func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Debugf("error reading %s#%s: %v", urlPrefix, filePath, err)
			return err
		}
		if d == nil {
			log.Debugf("nil entry for %s#%s", urlPrefix, filePath)
			return nil
		}
		if !c.lowerLicenseFileNames.Has(strings.ToLower(d.Name())) {
			return nil
		}
		rdr, err := fsys.Open(filePath)
		if err != nil {
			log.Debugf("error opening license file %s: %v", filePath, err)
			return nil
		}
		defer internal.CloseAndLogError(rdr, filePath)
		parsed, err := licenses.Parse(rdr, file.NewLocation(filePath))
		if err != nil {
			log.Debugf("error parsing license file %s: %v", filePath, err)
			return nil
		}
		// since these licenses are found in an external fs.FS, not in the scanned source,
		// get rid of the locations but keep information about the where the license was found
		// by prepending the urlPrefix to the internal path for an accurate representation
		for _, l := range toGoLicenses(parsed) {
			l.URLs = []string{urlPrefix + filePath}
			l.Locations = nil
			out = append(out, l)
		}
		return nil
	})
	return out, err
}

func (c *goLicenseResolver) findLicensesInSource(resolver file.Resolver, globMatch string) ([]goLicense, error) {
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

func getModule(proxies []string, moduleName, moduleVersion string) (urlPrefix string, fsys fs.FS, err error) {
	for _, proxy := range proxies {
		u, _ := url.Parse(proxy)
		if proxy == "direct" {
			urlPrefix, fsys, err = getModuleRepository(moduleName, moduleVersion)
			continue
		}
		switch u.Scheme {
		case "https", "http":
			urlPrefix, fsys, err = getModuleProxy(proxy, moduleName, moduleVersion)
		case "file":
			p := filepath.Join(u.Path, moduleName, "@v", moduleVersion)
			urlPrefix = path.Join("file://", p) + "/"
			fsys = os.DirFS(p)
		}
		if fsys != nil {
			break
		}
	}
	return
}

func getModuleProxy(proxy string, moduleName string, moduleVersion string) (moduleURL string, out fs.FS, _ error) {
	u := fmt.Sprintf("%s/%s/@v/%s.zip", proxy, moduleName, moduleVersion)

	// get the module zip
	resp, err := http.Get(u) //nolint:gosec
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		u = fmt.Sprintf("%s/%s/@v/%s.zip", proxy, strings.ToLower(moduleName), moduleVersion)

		// try lowercasing it; some packages have mixed casing that really messes up the proxy
		resp, err = http.Get(u) //nolint:gosec
		if err != nil {
			return "", nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return "", nil, fmt.Errorf("failed to get module zip: %s", resp.Status)
		}
	}

	// read the zip
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	out, err = zip.NewReader(bytes.NewReader(b), resp.ContentLength)
	versionPath := findVersionPath(out, ".")
	out = getSubFS(out, versionPath)

	return u + "#" + versionPath + "/", out, err
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

func getModuleRepository(moduleName string, moduleVersion string) (string, fs.FS, error) {
	repoName := moduleName
	parts := strings.Split(moduleName, "/")
	if len(parts) > 2 {
		repoName = fmt.Sprintf("%s/%s/%s", parts[0], parts[1], parts[2])
	}

	// see if there's a hash and use that if so, otherwise use a tag
	splitVersion := strings.Split(moduleVersion, "-")
	var cloneRefName plumbing.ReferenceName
	refPath := ""
	if len(splitVersion) < 3 {
		tagName := splitVersion[0]
		cloneRefName = plumbing.NewTagReferenceName(tagName)
		refPath = "/tags/" + tagName
	}

	f := memfs.New()
	buf := &bytes.Buffer{}
	repoURL := fmt.Sprintf("https://%s", repoName)
	r, err := git.Clone(memory.NewStorage(), f, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: cloneRefName,
		SingleBranch:  true,
		Depth:         1,
		Progress:      buf,
	})
	if err != nil {
		return "", nil, fmt.Errorf("%w -- %s", err, buf.String())
	}

	if len(splitVersion) > 2 {
		sha := splitVersion[len(splitVersion)-1]
		hash, err := r.ResolveRevision(plumbing.Revision(sha))
		if err != nil || hash == nil {
			log.Tracef("unable to resolve hash %s: %v", sha, err)
		} else {
			w, err := r.Worktree()
			if err != nil {
				log.Tracef("unable to get worktree, using default: %v", err)
			}
			err = w.Checkout(&git.CheckoutOptions{
				Hash: *hash,
			})
			if err != nil {
				log.Tracef("unable to checkout commit, using default: %v", err)
			} else {
				refPath = "/refs/" + hash.String()
			}
		}
	}

	return repoURL + refPath + "/", billyFSAdapter{fs: f}, err
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
