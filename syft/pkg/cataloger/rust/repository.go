package rust

import (
	"encoding/json"
	"fmt"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"io"
	"net/http"
	"os"
	"strings"
)

type RepositoryConfig struct {
	Download     string `json:"dl"`
	API          string `json:"api"`
	AuthRequired bool   `json:"auth-required"`
}

type SourceId struct {
	kind string
	url  string
}

func (i *SourceId) IsLocalSource() bool {
	return i.kind == SourceKindLocalRegistry
}

func GetSourceId(r *CargoLockEntry) (*SourceId, error) {
	if len(r.Source) == 0 {
		//Todo: add handling for looking in the current workspace, finding all Cargo.toml's and checking if any matches.
		//		if a match is found license information could potentially still be added.
		//	 	In that scenario adding "path" or "directory" support might make sense.
		return nil, fmt.Errorf("no Source was found for Dependency with Name %s and Version %s", r.Name, r.Version)
	}
	var before, after, found = strings.Cut(r.Source, "+")
	if !found {
		return nil, fmt.Errorf("did not find \"+\" in source field of dependency: Name: %s, Version: %s, Source: %s", r.Name, r.Version, r.Source)
	}

	return &SourceId{
		kind: before,
		url:  after,
	}, nil
}

// see https://github.com/rust-lang/cargo/blob/master/crates/cargo-util-schemas/src/core/source_kind.rs
const (
	SourceKindPath           = "path"
	SourceKindGit            = "git"
	SourceKindRegistry       = "registry"
	SourceKindLocalRegistry  = "local-registry"
	SourceKindSparse         = "sparse"
	SourceKindLocalDirectory = "directory"
)

const (
	Crate          = "{crate}"
	Version        = "{version}"
	Prefix         = "{prefix}"
	LowerPrefix    = "{lowerprefix}"
	Sha256Checksum = "{sha256-checksum}"
)

var RegistryRepos = make(map[string]*memory.Storage)
var RegistryConfig = make(map[string]RepositoryConfig)

// RepositoryConfigName see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/registry/mod.rs#L962
const RepositoryConfigName = "config.json"

func (i *SourceId) GetConfig() (*RepositoryConfig, error) {
	if i.kind == SourceKindLocalRegistry {
		//see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/registry/local.rs#L14-L57
		return &RepositoryConfig{
			Download:     fmt.Sprintf("%s/%s-%s.crate", i.url, Crate, Version),
			API:          "",
			AuthRequired: false,
		}, nil
	}
	if repoConfig, ok := RegistryConfig[i.url]; ok {
		return &repoConfig, nil
	}
	content, err := i.GetPath(RepositoryConfigName)
	if err != nil {
		return nil, err
	}
	var repoConfig = RepositoryConfig{}
	err = json.Unmarshal(content, &repoConfig)
	if err != nil {
		err = fmt.Errorf("failed to deserialize rust repository configuration: %s", err)
	}
	RegistryConfig[i.url] = repoConfig
	return &repoConfig, err
}

func (i *SourceId) GetPath(path string) ([]byte, error) {
	var content []byte
	switch i.kind {
	case SourceKindLocalRegistry:
		if path == RepositoryConfigName {
			return nil, nil
		}
		return os.ReadFile(fmt.Sprintf("%s/index/%s", i.url, path))
	case SourceKindSparse:
		resp, err := http.Get(fmt.Sprintf("%s/%s", i.url, path))
		if err != nil {
			return content, fmt.Errorf("could not get the path %s/%s from sparse registry: %s", i.url, path, err)
		}
		content, err = io.ReadAll(resp.Body)
		if err != nil {
			err = fmt.Errorf("failed to get contents of response %s: %s", path, err)
		}
		return content, err
	case SourceKindRegistry:
		_, repo, err := getOrInitRepo(i.url)
		if err != nil {
			return content, err
		}
		tree, err := getTree(repo)
		if err != nil {
			return content, err
		}
		file, err := tree.File(path)
		if err != nil {
			return content, fmt.Errorf("failed to find path %s in tree: %s", path, err)
		}
		reader, err := file.Reader()
		if err != nil {
			err = fmt.Errorf("failed to get reader for file %s: %s", path, err)
		}
		content, err = io.ReadAll(reader)
		if err != nil {
			err = fmt.Errorf("failed to get contents of file %s: %s", path, err)
		}
		return content, err
	}
	return content, fmt.Errorf("unsupported Remote")
}

func getOrInitRepo(url string) (*memory.Storage, *git.Repository, error) {
	var repo *git.Repository = nil
	var err error = nil

	var storage, ok = RegistryRepos[url]
	//Todo: Should we use an on-disk storage?
	if !ok {
		storage = memory.NewStorage()
		RegistryRepos[url] = storage
		repo, err = git.Init(storage, memfs.New())
		if err != nil {
			return storage, nil, fmt.Errorf("unable to initialise repo: %s", err)
		}
		err = updateRepo(repo, url)
		if err != nil {
			err = fmt.Errorf("unable to fetch registry information: %s", err)
		}
	} else {
		repo, err = git.Open(storage, memfs.New())
		if err != nil {
			err = fmt.Errorf("unable to open repository: %s", err)
		}
	}
	return storage, repo, err
}

func updateRepo(repo *git.Repository, url string) error {
	//Todo: cargo re-initialises the repo, if the fetch fails. Do we need to copy that?
	//see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/git/utils.rs#L1150
	remote, err := repo.CreateRemoteAnonymous(&config.RemoteConfig{
		Name:   "anonymous",
		URLs:   []string{url},
		Mirror: false,
		//see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/git/utils.rs#L979
		Fetch: []config.RefSpec{"+HEAD:refs/remotes/origin/HEAD"},
	})
	if err != nil {
		return fmt.Errorf("failed to create anonymous remote for url %s: %s", url, err)
	}
	err = remote.Fetch(&git.FetchOptions{
		RemoteName: "origin",
		Depth:      1,
		//Todo: support private repos by allowing auth information to be specified
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
		return fmt.Errorf("failed to fetch registry information from url %s: %s", url, err)
	}
	return err
}

func getTree(repo *git.Repository) (*object.Tree, error) {
	ref, err := repo.Reference("refs/remotes/origin/HEAD", true)
	if err != nil {
		return nil, fmt.Errorf("failed to get reference to refs/remotes/origin/HEAD: %s", err)
	}

	var hash = ref.Hash()
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit from repo head: %s", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tree from Commit: %s", err)
	}

	return tree, err
}
