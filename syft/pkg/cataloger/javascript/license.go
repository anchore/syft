package javascript

import (
	"context"
	"fmt"
	"sync"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// javascriptLicenseResolver resolves licenses for a package from the npm registry, backed by syft's
// on-disk cache so that the same package/version is only fetched once -- both within a single run
// (the same dependency is commonly present in several lockfiles) and across runs.
//
// This mirrors the python cataloger's license resolver (see syft/pkg/cataloger/python/license.go)
// with one deliberate difference: errors are not cached (cache.GetResolver rather than
// cache.GetResolverCachingErrors). A missing license silently weakens downstream license policy
// checks, so a transient registry failure (a 429, an outage) or a private package name that 404s
// against the public registry must not be able to blank out licenses for the lifetime of the cache
// entry. A successful lookup that returns an empty license is a real answer and is still cached.
type javascriptLicenseResolver struct {
	catalogerConfig CatalogerConfig
	licenseCache    cache.Resolver[string]
	prefetchCache   *sync.Map
}

func newJavascriptLicenseResolver(config CatalogerConfig) javascriptLicenseResolver {
	return javascriptLicenseResolver{
		licenseCache:    cache.GetResolver[string]("javascript", "v1"),
		catalogerConfig: config,
		prefetchCache:   &sync.Map{},
	}
}

func (lr *javascriptLicenseResolver) getLicenses(ctx context.Context, packageName string, packageVersion string) pkg.LicenseSet {
	var licenseSet pkg.LicenseSet

	if lr.catalogerConfig.SearchRemoteLicenses {
		license, err := lr.getLicensesFromRemote(packageName, packageVersion)
		if err == nil && license != "" {
			licenseSet = pkg.NewLicenseSet(pkg.NewLicensesFromValuesWithContext(ctx, license)...)
		}
		if err != nil {
			log.Debugf("unable to extract licenses from npm registry for package %s:%s: %+v", packageName, packageVersion, err)
		}
	}
	return licenseSet
}

func (lr *javascriptLicenseResolver) getLicensesFromRemote(packageName string, packageVersion string) (string, error) {
	key := fmt.Sprintf("%s/%s", packageName, packageVersion)
	if value, ok := lr.prefetchCache.Load(key); ok {
		return value.(string), nil
	}

	license, err := lr.licenseCache.Resolve(key, func() (string, error) {
		return getLicenseFromNpmRegistry(lr.catalogerConfig.NPMBaseURL, packageName, packageVersion)
	})
	if err == nil {
		lr.prefetchCache.Store(key, license)
	}
	return license, err
}
