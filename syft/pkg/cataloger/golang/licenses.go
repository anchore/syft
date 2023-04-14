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

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/source"
)

type goLicenses struct {
	opts                  GoCatalogerOpts
	localModCacheResolver source.WritableFileResolver
	progress              *event.CatalogerTask
}

func newGoLicenses(opts GoCatalogerOpts) goLicenses {
	return goLicenses{
		opts:                  opts,
		localModCacheResolver: modCacheResolver(opts.localModCacheDir),
		progress: &event.CatalogerTask{
			SubStatus:          true,
			RemoveOnCompletion: true,
			Title:              "Downloading go mod",
		},
	}
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

func modCacheResolver(modCacheDir string) source.WritableFileResolver {
	var r source.WritableFileResolver

	if modCacheDir == "" {
		log.Trace("unable to determine mod cache directory, skipping mod cache resolver")
		r = source.NewMockResolverForPaths()
	} else {
		stat, err := os.Stat(modCacheDir)

		if os.IsNotExist(err) || stat == nil || !stat.IsDir() {
			log.Tracef("unable to open mod cache directory: %s, skipping mod cache resolver", modCacheDir)
			r = source.NewMockResolverForPaths()
		} else {
			r = source.NewUnindexedDirectoryResolver(modCacheDir)
		}
	}

	return r
}

//nolint:gocognit
func (c *goLicenses) getLicenses(resolver source.FileResolver, moduleName, moduleVersion string) (licenses []string, err error) {
	licenses, err = findLicenses(resolver,
		fmt.Sprintf(`**/go/pkg/mod/%s@%s/*`, processCaps(moduleName), moduleVersion),
	)

	search := c.opts.searchLocalModCacheLicenses || c.opts.searchRemoteLicenses
	dir := fmt.Sprintf("%s@%s", processCaps(moduleName), moduleVersion)
	glob := fmt.Sprintf("%s/*", dir)

	if search && err == nil && len(licenses) == 0 {
		// if we're running against a directory on the filesystem, it may not include the
		// user's homedir / GOPATH, so we defer to using the localModCacheResolver
		licenses, err = findLicenses(c.localModCacheResolver, glob)
	}

	// if we did not find it yet, and remote searching was enabled, then use that
	if c.opts.searchRemoteLicenses && err == nil && len(licenses) == 0 {
		proxies := remotesForModule(c.opts.proxies, c.opts.noProxy, moduleName)

		var fsys fs.FS
		fsys, err = getModule(c.progress, proxies, moduleName, moduleVersion)
		if err == nil {
			// populate the mod cache with the results
			err = fs.WalkDir(fsys, ".", func(filePath string, d fs.DirEntry, err error) error {
				if err != nil {
					log.Debug(err)
					return nil
				}
				if d.IsDir() {
					return nil
				}
				f, err := fsys.Open(filePath)
				if err != nil {
					return err
				}
				return c.localModCacheResolver.Write(source.NewLocation(path.Join(dir, filePath)), f)
			})

			if err != nil {
				log.Tracef("remote proxy walk failed for: %s", moduleName)
			}

			if err == nil {
				// re-scan the mod cache
				licenses, err = findLicenses(c.localModCacheResolver, glob)
			}
		}
	}

	// always return a non-nil slice
	if licenses == nil {
		licenses = []string{}
	}

	return licenses, err
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

func getModule(progress *event.CatalogerTask, proxies []string, moduleName, moduleVersion string) (fsys fs.FS, err error) {
	for _, proxy := range proxies {
		u, _ := url.Parse(proxy)
		if proxy == "direct" {
			fsys, err = getModuleRepository(progress, moduleName, moduleVersion)
			continue
		}
		switch u.Scheme {
		case "https", "http":
			fsys, err = getModuleProxy(progress, proxy, moduleName, moduleVersion)
		case "file":
			p := filepath.Join(u.Path, moduleName, "@v", moduleVersion)
			progress.SetValue(fmt.Sprintf("file: %s", p))
			fsys = os.DirFS(p)
		}
		if fsys != nil {
			break
		}
	}
	return
}

//nolint:gosec
func getModuleProxy(progress *event.CatalogerTask, proxy string, moduleName string, moduleVersion string) (out fs.FS, _ error) {
	u := fmt.Sprintf("%s/%s/@v/%s.zip", proxy, moduleName, moduleVersion)
	progress.SetValue(u)
	// get the module zip
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		u = fmt.Sprintf("%s/%s/@v/%s.zip", proxy, strings.ToLower(moduleName), moduleVersion)
		progress.SetValue(u)
		// try lowercasing it; some packages have mixed casing that really messes up the proxy
		resp, err = http.Get(u)
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

func getModuleRepository(progress *event.CatalogerTask, moduleName string, moduleVersion string) (fs.FS, error) {
	repoName := moduleName
	parts := strings.Split(moduleName, "/")
	if len(parts) > 2 {
		repoName = fmt.Sprintf("%s/%s/%s", parts[0], parts[1], parts[2])
	}
	progress.SetValue(fmt.Sprintf("git: %s", repoName))
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
