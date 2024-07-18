package cargo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
)

// see https://github.com/rust-lang/cargo/blob/master/crates/cargo-util-schemas/src/core/source_kind.rs
const (
	sourceKindPath           = "path"
	sourceKindGit            = "git"
	sourceKindRegistry       = "registry"
	sourceKindLocalRegistry  = "local-registry"
	sourceKindSparse         = "sparse"
	sourceKindLocalDirectory = "directory"

	crate          = "{crate}"
	version        = "{version}"
	prefix         = "{prefix}"
	lowerPrefix    = "{lowerprefix}"
	sha256Checksum = "{sha256-checksum}"

	// registryConfigName see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/registry/mod.rs#L962
	registryConfigName = "config.json"
)

type RegistryInfo struct {
	IsLocalFile bool
	RepositoryConfig
}

type RepositoryConfig struct {
	Download string `json:"dl"`
}

type registryResolver struct {
	onlineEnabled          bool
	registryGitRepoObjects map[string]*memory.Storage
	registryCache          cache.Resolver[RegistryInfo]
	http                   httpGetter
}

type sourceID struct {
	kind string
	url  string
}

func newRegistryResolver(onlineEnabled bool) registryResolver {
	return registryResolver{
		onlineEnabled:          onlineEnabled,
		registryGitRepoObjects: make(map[string]*memory.Storage),
		registryCache:          cache.GetResolverCachingErrors[RegistryInfo]("cargo/registry", "v1"),
		http:                   http.DefaultClient,
	}
}

func (r *registryResolver) resolve(entry LockEntry) (RegistryInfo, error) {
	if entry.RegistryInfo != nil {
		return *entry.RegistryInfo, nil
	}

	if !r.onlineEnabled {
		return RegistryInfo{}, nil
	}

	return r.registryCache.Resolve(entry.Source, registryAdapter{
		entry:                  entry,
		registryGitRepoObjects: r.registryGitRepoObjects,
		onlineEnabled:          r.onlineEnabled,
		http:                   r.http,
	}.fetch)
}

type registryAdapter struct {
	entry                  LockEntry
	registryGitRepoObjects map[string]*memory.Storage
	onlineEnabled          bool
	http                   httpGetter
}

type httpGetter interface {
	Get(url string) (*http.Response, error)
}

func (r registryAdapter) fetch() (RegistryInfo, error) {
	if !r.onlineEnabled {
		return RegistryInfo{}, nil
	}

	sID := r.entry.sourceID()
	if sID == nil {
		return RegistryInfo{}, nil
	}

	repoConfig, err := r.getRegistryConfig(*sID)
	if err != nil {
		return RegistryInfo{}, err
	}

	return RegistryInfo{
		IsLocalFile:      sID.kind == sourceKindLocalRegistry,
		RepositoryConfig: *repoConfig,
	}, nil
}

func (r registryAdapter) getRegistryConfig(i sourceID) (*RepositoryConfig, error) {
	if i.kind == sourceKindLocalRegistry {
		// see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/registry/local.rs#L14-L57
		return &RepositoryConfig{
			Download: fmt.Sprintf("%s/%s-%s.crate", i.url, crate, version),
		}, nil
	}

	content, err := r.fetchRegistryConfigContents(i)
	if err != nil {
		return nil, err
	}

	var repoConfig RepositoryConfig
	err = json.Unmarshal(content, &repoConfig)

	log.WithFields("url", i.url, "kind", i.kind, "repo-dl", repoConfig.Download, "error", err).Tracef("rust cargo repo config: %s", string(content))

	if err != nil {
		err = fmt.Errorf("failed to deserialize rust repository configuration: %w", err)
	}
	return &repoConfig, err
}

func (r registryAdapter) fetchRegistryConfigContents(i sourceID) ([]byte, error) {
	path := registryConfigName
	var content []byte
	switch i.kind {
	case sourceKindLocalRegistry:
		return nil, nil

		// if path == registryConfigName {
		//	return nil, nil
		//}

		// TODO: when would this ever be true?
		// return os.ReadFile(fmt.Sprintf("%s/index/%s", i.url, path))

	case sourceKindSparse:
		if !r.onlineEnabled {
			return nil, nil
		}
		resp, err := r.http.Get(fmt.Sprintf("%s/%s", i.url, path))
		if err != nil {
			return content, fmt.Errorf("could not get the path %s/%s from sparse registry: %w", i.url, path, err)
		}

		content, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			err = fmt.Errorf("failed to get contents of response %s: %w", path, err)
		}

		return content, err

	case sourceKindRegistry:
		if !r.onlineEnabled {
			return nil, nil
		}

		_, repo, err := r.getOrInitRepo(i.url)
		if err != nil {
			return content, err
		}
		tree, err := getTree(repo)
		if err != nil {
			return content, err
		}
		file, err := tree.File(path)
		if err != nil {
			return content, fmt.Errorf("failed to find path %s in tree: %w", path, err)
		}
		reader, err := file.Reader()
		if err != nil {
			return content, fmt.Errorf("failed to get reader for file %s: %w", path, err)
		}
		content, err = io.ReadAll(reader)
		if err != nil {
			return content, fmt.Errorf("failed to get contents of file %s: %w", path, err)
		}

		return content, err
	}
	return content, fmt.Errorf("unsupported Remote")
}

func (r registryAdapter) getOrInitRepo(url string) (*memory.Storage, *git.Repository, error) {
	var repo *git.Repository
	var err error

	// Todo: Should we use an on-disk storage?
	var storage, ok = r.registryGitRepoObjects[url]
	if !ok {
		storage = memory.NewStorage()
		r.registryGitRepoObjects[url] = storage
		repo, err = git.Init(storage, memfs.New())
		if err != nil {
			return storage, nil, fmt.Errorf("unable to initialise repo: %w", err)
		}
		err = updateRepo(repo, url)
		if err != nil {
			err = fmt.Errorf("unable to fetch registry information: %w", err)
		}
	} else {
		repo, err = git.Open(storage, memfs.New())
		if err != nil {
			err = fmt.Errorf("unable to open repository: %w", err)
		}
	}

	return storage, repo, err
}

func updateRepo(repo *git.Repository, url string) error {
	// Todo: cargo re-initialises the repo, if the fetch fails. Do we need to copy that?
	// see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/git/utils.rs#L1150
	remote, err := repo.CreateRemoteAnonymous(&config.RemoteConfig{
		Name:   "anonymous",
		URLs:   []string{url},
		Mirror: false,
		// see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/git/utils.rs#L979
		Fetch: []config.RefSpec{"+HEAD:refs/remotes/origin/HEAD"},
	})
	if err != nil {
		return fmt.Errorf("failed to create anonymous remote for url %s: %w", url, err)
	}
	err = remote.Fetch(&git.FetchOptions{
		RemoteName: "origin",
		Depth:      1,
		// Todo: support private repos by allowing auth information to be specified
		Auth:            nil,
		Progress:        nil,
		Tags:            git.NoTags,
		Force:           false,
		InsecureSkipTLS: false,
		CABundle:        nil,
		ProxyOptions:    transport.ProxyOptions{},
		Prune:           false,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch registry information from url %s: %w", url, err)
	}
	return err
}

func getTree(repo *git.Repository) (*object.Tree, error) {
	ref, err := repo.Reference("refs/remotes/origin/HEAD", true)
	if err != nil {
		return nil, fmt.Errorf("failed to get reference to refs/remotes/origin/HEAD: %w", err)
	}

	var hash = ref.Hash()
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit from repo head: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tree from Commit: %w", err)
	}

	return tree, err
}
