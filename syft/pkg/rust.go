package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/spdx/tools-golang/spdx"
	"strings"
)

type RustCargoLockEntry struct {
	CargoLockVersion int      `toml:"-" json:"-"`
	Name             string   `toml:"name" json:"name"`
	Version          string   `toml:"version" json:"version"`
	Source           string   `toml:"source" json:"source"`
	Checksum         string   `toml:"checksum" json:"checksum"`
	Dependencies     []string `toml:"dependencies" json:"dependencies"`
}

type RustBinaryAuditEntry struct {
	Name    string `toml:"name" json:"name"`
	Version string `toml:"version" json:"version"`
	Source  string `toml:"source" json:"source"`
}

type RustRepositoryConfig struct {
	Download     string `json:"dl"`
	API          string `json:"api"`
	AuthRequired bool   `json:"auth-required"`
}

type SourceId struct {
	kind string
	url  string
}

type DependencyInformation struct {
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

var RegistryRepos = make(map[string]*memory.Storage)
var RegistryConfig = make(map[string]RustRepositoryConfig)

// GetChecksumType This exists, to made adopting new potential cargo.lock versions easier
func (r *RustCargoLockEntry) GetChecksumType() spdx.ChecksumAlgorithm {
	//Cargo currently always uses Sha256: https://github.com/rust-lang/cargo/blob/a9ee3e82b57df019dfc0385f844bc6928150ee63/src/cargo/sources/registry/download.rs#L125
	return spdx.SHA256
}

func (r *RustCargoLockEntry) getSourceId() (*SourceId, error) {
	var before, after, found = strings.Cut(r.Source, "+")
	if !found {
		return nil, fmt.Errorf("did not find \"+\" in source field of dependency: Name: %s, Version: %s, Source: %s", r.Name, r.Version, r.Source)
	}

	return &SourceId{
		kind: before,
		url:  after,
	}, nil
}

// GetPrefix get {path} for https://doc.rust-lang.org/cargo/reference/registry-index.html
func (r *RustCargoLockEntry) GetPrefix() string {
	switch len(r.Name) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("1/%s", r.Name[0:1])
	case 2:
		return fmt.Sprintf("2/%s", r.Name[0:2])
	case 3:
		return fmt.Sprintf("3/%s", r.Name[0:1])
	default:
		return fmt.Sprintf("%s/%s", r.Name[0:2], r.Name[2:4])
	}
}

func (r *RustCargoLockEntry) GetDownloadLink() (string, error) {
	var sourceId, err = r.getSourceId()
	if err != nil {
		return "", err
	}
	var repoConfig *RustRepositoryConfig = nil
	repoConfig, err = sourceId.GetConfig()
	if err != nil {
		return "", err
	}
	return r.getDownloadLink(repoConfig.Download), err
}

func (r *RustCargoLockEntry) getDownloadLink(url string) string {
	const Crate = "{crate}"
	const Version = "{version}"
	const Prefix = "{prefix}"
	const LowerPrefix = "{lowerprefix}"
	const Sha256Checksum = "{sha256-checksum}"
	if !strings.Contains(url, Crate) &&
		!strings.Contains(url, Version) &&
		!strings.Contains(url, Prefix) &&
		!strings.Contains(url, LowerPrefix) &&
		!strings.Contains(url, Sha256Checksum) {
		return url + fmt.Sprintf("/%s/%s/download", r.Name, r.Version)
	}

	var link = url
	link = strings.ReplaceAll(link, Crate, r.Name)
	link = strings.ReplaceAll(link, Version, r.Version)
	link = strings.ReplaceAll(link, Prefix, r.GetPrefix())
	link = strings.ReplaceAll(link, LowerPrefix, strings.ToLower(r.GetPrefix()))
	link = strings.ReplaceAll(link, Sha256Checksum, r.Checksum)
	return link
}
func (r *RustCargoLockEntry) getIndexPath() string {
	return fmt.Sprintf("%s/%s", strings.ToLower(r.GetPrefix()), strings.ToLower(r.Name))
}

// RepositoryConfigName see https://github.com/rust-lang/cargo/blob/b134eff5cedcaa4879f60035d62630400e7fd543/src/cargo/sources/registry/mod.rs#L962
const RepositoryConfigName = "config.json"

func (i *SourceId) GetConfig() (*RustRepositoryConfig, error) {
	if repoConfig, ok := RegistryConfig[i.url]; ok {
		return &repoConfig, nil
	}
	content, err := i.GetPath(RepositoryConfigName)
	if err != nil {
		return nil, err
	}
	var repoConfig = RustRepositoryConfig{}
	err = json.Unmarshal([]byte(content), &repoConfig)
	if err != nil {
		err = fmt.Errorf("failed to deserialize rust repository configuration: %s", err)
	}
	RegistryConfig[i.url] = repoConfig
	return &repoConfig, err
}

func (i *SourceId) GetPath(path string) (string, error) {
	switch i.kind {
	case SourceKindRegistry:
		var content = ""
		var tree, err = getTree(i.url)
		if err != nil {
			return content, err
		}
		var file *object.File = nil
		file, err = tree.File(path)
		if err != nil {
			return content, fmt.Errorf("failed to find path %s in tree: %s", path, err)
		}
		content, err = file.Contents()
		if err != nil {
			err = fmt.Errorf("failed to get contents of file %s: %s", path, err)
		}
		return content, err
	}
	return "", fmt.Errorf("unsupported Remote")
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
	var remote, err = repo.CreateRemoteAnonymous(&config.RemoteConfig{
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

func getTree(url string) (*object.Tree, error) {
	var _, repo, err = getOrInitRepo(url)
	if err != nil {
		return nil, err
	}

	var ref *plumbing.Reference = nil
	ref, err = repo.Reference("refs/remotes/origin/HEAD", true)
	if err != nil {
		return nil, fmt.Errorf("failed to get reference to refs/remotes/origin/HEAD: %s", err)
	}

	var hash = ref.Hash()
	var commit *object.Commit = nil
	commit, err = repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit from repo head: %s", err)
	}

	var tree *object.Tree = nil
	tree, err = commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tree from Commit: %s", err)
	}

	return tree, err
}
