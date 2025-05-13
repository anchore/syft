package golang

import (
	"archive/zip"
	"bytes"
	"context"
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
	"github.com/anchore/syft/syft/pkg"
)

type goLicenseResolver struct {
	catalogerName         string
	opts                  CatalogerConfig
	localModCacheDir      fs.FS
	localVendorDir        fs.FS
	licenseCache          cache.Resolver[[]pkg.License]
	lowerLicenseFileNames *strset.Set
}

func newGoLicenseResolver(catalogerName string, opts CatalogerConfig) goLicenseResolver {
	var localModCacheDir fs.FS
	if opts.SearchLocalModCacheLicenses {
		localModCacheDir = os.DirFS(opts.LocalModCacheDir)
	}

	var localVendorDir fs.FS
	if opts.SearchLocalVendorLicenses {
		vendorDir := opts.LocalVendorDir
		if vendorDir == "" {
			wd, err := os.Getwd()
			if err != nil {
				log.Debugf("unable to get CWD while resolving the local go vendor dir: %v", err)
			} else {
				vendorDir = filepath.Join(wd, "vendor")
			}
		}
		localVendorDir = os.DirFS(vendorDir)
	}

	return goLicenseResolver{
		catalogerName:         catalogerName,
		opts:                  opts,
		localModCacheDir:      localModCacheDir,
		localVendorDir:        localVendorDir,
		licenseCache:          cache.GetResolverCachingErrors[[]pkg.License]("golang", "v2"),
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

func (c *goLicenseResolver) getLicenses(ctx context.Context, resolver file.Resolver, moduleName, moduleVersion string) []pkg.License {
	// search the scan target first, ignoring local and remote sources
	pkgLicenses, err := c.findLicensesInSource(ctx, resolver,
		fmt.Sprintf(`**/go/pkg/mod/%s@%s/*`, processCaps(moduleName), moduleVersion),
	)
	if err != nil {
		log.WithFields("error", err, "module", moduleName, "version", moduleVersion).Trace("unable to read golang licenses from source")
	}
	if len(pkgLicenses) > 0 {
		return pkgLicenses
	}

	// look in the local host mod directory...
	if c.opts.SearchLocalModCacheLicenses {
		pkgLicenses, err = c.getLicensesFromLocal(ctx, moduleName, moduleVersion)
		if err != nil {
			log.WithFields("error", err, "module", moduleName, "version", moduleVersion).Trace("unable to read golang licenses local")
		}
		if len(pkgLicenses) > 0 {
			return pkgLicenses
		}
	}

	// look in the local vendor directory...
	if c.opts.SearchLocalVendorLicenses {
		pkgLicenses, err = c.getLicensesFromLocalVendor(ctx, moduleName)
		if err != nil {
			log.WithFields("error", err, "module", moduleName, "version", moduleVersion).Trace("unable to read golang licenses vendor")
		}
		if len(pkgLicenses) > 0 {
			return pkgLicenses
		}
	}

	// download from remote sources
	if c.opts.SearchRemoteLicenses {
		pkgLicenses, err = c.getLicensesFromRemote(ctx, moduleName, moduleVersion)
		if err != nil {
			log.WithFields("error", err, "module", moduleName, "version", moduleVersion).Debug("unable to read golang licenses remote")
		}
	}

	return pkgLicenses
}

func (c *goLicenseResolver) getLicensesFromLocal(ctx context.Context, moduleName, moduleVersion string) ([]pkg.License, error) {
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
	return c.findLicensesInFS(ctx, "file://$GOPATH/pkg/mod/"+subdir+"/", dir)
}

func (c *goLicenseResolver) getLicensesFromLocalVendor(ctx context.Context, moduleName string) ([]pkg.License, error) {
	if c.localVendorDir == nil {
		return nil, nil
	}

	subdir := processCaps(moduleName)

	// get the local subdirectory containing the specific go module
	dir, err := fs.Sub(c.localVendorDir, subdir)
	if err != nil {
		return nil, err
	}

	// if we're running against a directory on the filesystem, it may not include the
	// user's homedir / GOPATH, so we defer to using the localModCacheResolver
	// we use $GOPATH/pkg/mod to avoid leaking information about the user's system
	return c.findLicensesInFS(ctx, "file://$GO_VENDOR/"+subdir+"/", dir)
}

func (c *goLicenseResolver) getLicensesFromRemote(ctx context.Context, moduleName, moduleVersion string) ([]pkg.License, error) {
	return c.licenseCache.Resolve(fmt.Sprintf("%s/%s", moduleName, moduleVersion), func() ([]pkg.License, error) {
		proxies := remotesForModule(c.opts.Proxies, c.opts.NoProxy, moduleName)

		urlPrefix, fsys, err := getModule(proxies, moduleName, moduleVersion)
		if err != nil {
			return nil, err
		}

		return c.findLicensesInFS(ctx, urlPrefix, fsys)
	})
}

func (c *goLicenseResolver) findLicensesInFS(ctx context.Context, urlPrefix string, fsys fs.FS) ([]pkg.License, error) {
	var out []pkg.License
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
		licenses := pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(file.NewLocation(filePath), rdr))
		// since these licenses are found in an external fs.FS, not in the scanned source,
		// get rid of the locations but keep information about the where the license was found
		// by prepending the urlPrefix to the internal path for an accurate representation
		for _, l := range licenses {
			l.URLs = []string{urlPrefix + filePath}
			l.Locations = file.NewLocationSet()
			out = append(out, l)
		}
		return nil
	})
	return out, err
}

func (c *goLicenseResolver) findLicensesInSource(ctx context.Context, resolver file.Resolver, globMatch string) ([]pkg.License, error) {
	var out []pkg.License
	locations, err := resolver.FilesByGlob(globMatch)
	if err != nil {
		return nil, err
	}

	for _, l := range locations {
		parsed, err := c.parseLicenseFromLocation(ctx, l, resolver)
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

func (c *goLicenseResolver) parseLicenseFromLocation(ctx context.Context, l file.Location, resolver file.Resolver) ([]pkg.License, error) {
	var out []pkg.License
	fileName := path.Base(l.RealPath)
	if c.lowerLicenseFileNames.Has(strings.ToLower(fileName)) {
		contents, err := resolver.FileContentsByLocation(l)
		if err != nil {
			return nil, err
		}
		defer internal.CloseAndLogError(contents, l.RealPath)
		out = pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(l, contents))
	}
	return out, nil
}

func moduleDir(moduleName, moduleVersion string) string {
	return fmt.Sprintf("%s@%s", processCaps(moduleName), moduleVersion)
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
			log.WithFields("path", p).Info("looking for go module in filesystem")
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
	log.WithFields("url", u).Info("downloading go module from proxy")
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

	log.WithFields("repoURL", repoURL, "ref", cloneRefName).Info("cloning go module repository")
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
