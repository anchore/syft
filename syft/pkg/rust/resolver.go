package rust

import (
	"fmt"

	"github.com/anchore/syft/internal/cache"
)

type CargoInfoResolver struct {
	catalogerName string
	opts          CatalogerConfig
	crateCache    cache.Resolver[SourceGeneratedDepInfo]
	repoCache     cache.Resolver[RegistryGeneratedDepInfo]
}

func NewCargoInfoResolver(catalogerName string, opts CatalogerConfig) CargoInfoResolver {
	return CargoInfoResolver{
		catalogerName: catalogerName,
		opts:          opts,
		crateCache:    cache.GetResolverCachingErrors[SourceGeneratedDepInfo]("cargo/crate", "v1"),
		repoCache:     cache.GetResolverCachingErrors[RegistryGeneratedDepInfo]("cargo/repositoryConfig", "v1"),
	}
}

func (r *CargoInfoResolver) Resolve(entry RustCargoLockEntry) (SourceGeneratedDepInfo, error) {
	if entry.SourceGeneratedDepInfo != nil {
		return *entry.SourceGeneratedDepInfo, nil
	}
	if !r.opts.SearchRemote || entry.RegistryGeneratedDepInfo == nil {
		return EmptySourceGeneratedDepInfo(), fmt.Errorf("we are not allowed to search remotly for extra info")
	}

	return r.crateCache.Resolve(entry.Source, func() (SourceGeneratedDepInfo, error) {
		return entry.getGeneratedInformationUncached()
	})
}

func (r *CargoInfoResolver) ResolveRepo(entry RustCargoLockEntry) (RegistryGeneratedDepInfo, error) {
	if entry.RegistryGeneratedDepInfo != nil {
		return *entry.RegistryGeneratedDepInfo, nil
	}
	if !r.opts.SearchRemote {
		return EmptyRegistryGeneratedDepInfo(), fmt.Errorf("we are not allowed to search remotly for extra info")
	}

	return r.repoCache.Resolve(entry.Source, func() (RegistryGeneratedDepInfo, error) {
		return entry.toRegistryGeneratedDepInfo()
	})
}
