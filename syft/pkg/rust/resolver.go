package rust

import (
	"fmt"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/internal/cache"
)

type CargoInfoResolver struct {
	catalogerName string
	opts          CatalogerConfig
	crateCache    cache.Resolver[SourceGeneratedDepInfo]
	repoCache     cache.Resolver[RegistryGeneratedInfo]
}

func NewCargoInfoResolver(catalogerName string, inOpts CatalogerConfig) CargoInfoResolver {
	log.Warnf("initial cataloger config: %v", inOpts.SearchRemote)
	return CargoInfoResolver{
		catalogerName: catalogerName,
		opts:          inOpts,
		crateCache:    cache.GetResolverCachingErrors[SourceGeneratedDepInfo]("cargo/crate", "v1"),
		repoCache:     cache.GetResolverCachingErrors[RegistryGeneratedInfo]("cargo/RepositoryConfig", "v1"),
	}
}

func (r *CargoInfoResolver) Resolve(entry RustCargoLockEntry) (SourceGeneratedDepInfo, error) {
	if entry.SourceGeneratedDepInfo != nil {
		return *entry.SourceGeneratedDepInfo, nil
	}
	r.opts.SearchRemote = true //Todo: why is this always false?
	if !r.opts.SearchRemote {
		return EmptySourceGeneratedDepInfo(), fmt.Errorf("we are not allowed to search remotly for extra info")
	}
	if entry.RegistryGeneratedInfo == nil {
		return EmptySourceGeneratedDepInfo(), fmt.Errorf("no Registry Information present")
	}

	return r.crateCache.Resolve(entry.Source, entry.getGeneratedInformationUncached)
}

func (r *CargoInfoResolver) ResolveRepo(entry RustCargoLockEntry) (RegistryGeneratedInfo, error) {
	if entry.RegistryGeneratedInfo != nil {
		return *entry.RegistryGeneratedInfo, nil
	}

	r.opts.SearchRemote = true //Todo: why is this always false?
	if !r.opts.SearchRemote {
		return EmptyRegistryGeneratedDepInfo(), fmt.Errorf("we are not allowed to search remotly for extra info")
	}

	return r.repoCache.Resolve(entry.Source, entry.toRegistryGeneratedDepInfo)
}
