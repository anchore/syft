package vcpkg

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/syft/pkg"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

const vcpkgRepo string = "https://github.com/microsoft/vcpkg"
const vcpkgCacheKey string = "cpp/vcpkg/repo/v1"

type ManifestNode struct {
	Parent *pkg.VcpkgManifest
	Child *pkg.VcpkgManifest 
}

type ID struct {
	location string
	head string
	name    string
	version string
}

// Resolver is a short-lived utility to resolve maven poms from multiple sources, including:
// the scanned filesystem, local maven cache directories, remote maven repositories, and the syft cache
type Resolver struct {
	cfg                  pkg.VcpkgConfig
	cache                cache.Cache
	resolved             map[ID]*pkg.VcpkgManifest
}

// NewResolver constructs a new Resolver with the given vcpkg configuration.
func NewResolver(cfg pkg.VcpkgConfig) *Resolver {
	return &Resolver{
		cfg:                  cfg,
		resolved:             map[ID]*pkg.VcpkgManifest{},
	}
}

func getBuiltinRepo(repo string) (*git.Repository, error) {
	path := os.Getenv("VCPKG_ROOT")
	if path == "" {
		cachePath, err := getCachePath(vcpkgRepo)
		if err != nil {
			return nil, err
		}
		return getRepo(repo, cachePath)
	}
	return getRepo(repo, path)
}

func getRepo(repo, path string) (*git.Repository, error) {
	// needed in case it's a private custom git registry
	// sshPath := os.Getenv("HOME") + "/.ssh/gitlab"
	// publicKeys, err := ssh.NewPublicKeysFromFile("git", sshPath, "")
	r, err := git.PlainOpen(path)
	if err != nil {
		r, err = git.PlainClone(path, false, &git.CloneOptions{
			URL: repo,
		})
		if err != nil {
			return nil, fmt.Errorf("could not clone repo: %v", repo)
		}
	}
	return r, nil
}

func getCachePath(repo string) (string, error) {
	trimmedRepo := strings.TrimPrefix(strings.TrimPrefix(repo, "http://"), "https://")
	roots := cache.GetManager().RootDirs()
	if len(roots) == 0 {
		return "", fmt.Errorf("could not determine cache root")
	}
	return roots[0] + "/" + vcpkgCacheKey + "/" + trimmedRepo, nil
}

// Get all of the manifest/vcpkg.json files from github 
func (r *Resolver) FindManifests(ctx context.Context, dependency any, df bool, parent *pkg.VcpkgManifest) ([]ManifestNode, error) {
	var name string
	var version string
	defaultFeatures := df
	var features []any
	// can be either string or VcpkgDependency 
	switch d := dependency.(type) {
	case string:
		name = d
	case map[string]any:
		if d["name"] != nil {
			name = d["name"].(string) 
		}
		if d["version>="] != nil {
			version = d["version>="].(string)
		}
		if d["default-features"] != nil {
			defaultFeatures = defaultFeatures && d["default-features"].(bool)
		}
		if d["features"] != nil {
			features = d["features"].([]any)
		}
	}

	reg := r.depRegistry(name)

	manNodes := []ManifestNode{}
	var vcpkg pkg.VcpkgManifest 
	var err error
	switch reg.Kind {
	case pkg.Git:
		if reg.Repository == "" {	
			return nil, fmt.Errorf("No repo found for vcpkg git registry")
		}
		var gitRepo *git.Repository
		if reg.Repository == vcpkgRepo {
			gitRepo, err = getBuiltinRepo(vcpkgRepo)
		} else {
			cachePath, err := getCachePath(reg.Repository)
			if err != nil {
				return nil, err
			}
			gitRepo, err = getRepo(reg.Repository, cachePath)
		}
		vcpkg, err = r.findManifestWithGit(gitRepo, reg.Baseline, name, version)
		if err != nil {
			return nil, err 
		}
		id := ID{reg.Repository, reg.Baseline, name, version}
		r.resolved[id] = &vcpkg
	case pkg.Builtin:
		gitRepo, err := getBuiltinRepo(vcpkgRepo)
		vcpkg, err = r.findManifestWithGit(gitRepo, reg.Baseline, name, version)
		if err != nil {
			return nil, err 
		}
		id := ID{vcpkgRepo, reg.Baseline, name, version}
		r.resolved[id] = &vcpkg
	case pkg.FileSystem:
		if reg.Path == "" {
			return nil, fmt.Errorf("No path found for vcpkg filesystem registry. %w", err)
		}
		baseline := reg.Baseline 
		if baseline == "" {
			baseline = "default"
		}
		vcpkg, err = r.findManifestForFilesystemReg(reg.Path, baseline, name, version)
		if err != nil {
			return nil, err 
		}
		id := ID{reg.Path, reg.Baseline, name, version}
		r.resolved[id] = &vcpkg
	default:
		return nil, fmt.Errorf("vcpkg registry has no kind which is required. %w", err)
	}
	// some features pull in additional dependencies
	for _, feature := range features {
		switch fo := feature.(type) {
		case string:
			for name, f := range vcpkg.Features {
				if fo == name || (defaultFeatures && isDefaultFeature(name, vcpkg.DefaultFeatures)) {
					vcpkg.Dependencies = append(vcpkg.Dependencies, f.Dependencies...)
				}
			}
		case pkg.VcpkgFeatureObject:
			for name, f := range vcpkg.Features {
				if fo.Name == name || (defaultFeatures && isDefaultFeature(name, vcpkg.DefaultFeatures)) {
					vcpkg.Dependencies = append(vcpkg.Dependencies, f.Dependencies...)
				}
			}
		}
	}
	manNode := ManifestNode{
		Parent: parent,
		Child: &vcpkg,
	}
	manNodes = append(manNodes, manNode)
	if len(vcpkg.Dependencies) != 0 {
		for _, dep := range vcpkg.Dependencies {
			if !r.depResolved(dep) {
				childManNodes, err := r.FindManifests(ctx, dep, df, &vcpkg)
				if err != nil {
					return nil, fmt.Errorf("could not find vcpkg.json file for dependency. %w", err)
				}
				manNodes = append(manNodes, childManNodes...)
			}
		}
	}
	return manNodes, nil
}

func (r *Resolver) depRegistry(name string) pkg.VcpkgRegistry {
	var reg pkg.VcpkgRegistry
	// determines which registry to use
	for _, res := range r.cfg.Registries {
		for _, p := range res.Packages {
			if p == name {
				reg = res
			}
		}
	}
	// if package not specified use default registry
	if reg.Kind == "" {
		reg = r.cfg.DefaultRegistry
	}
	return reg
}

func (r *Resolver) depResolved(dep any) bool {
	var name string
	var version string
	switch d := dep.(type) {
	case string:
		name = d
	case map[string]any:
		if d["name"] != nil {
			name = d["name"].(string) 
		}
		if d["version>="] != nil {
			version = d["version>="].(string)
		}
	}
	reg := r.depRegistry(name)
	var location string
	if reg.Repository != "" {
		location = reg.Repository
	} else if reg.Path != "" {
		location = reg.Path
	} else {
		location = vcpkgRepo
	}
	_, ok := r.resolved[ID{location, reg.Baseline, name, version}]
	return ok
}

func isDefaultFeature(name string, defaultFeatures []any) bool {
	for _, df := range defaultFeatures {
		switch d := df.(type) {
			case string:
				if name == d {
					return true
				}
			case map[string]any:
				if name == d["name"].(string) {
					return true
				}
		}
	}
	return false
}

// Clones the repo to find the vcpkg.json file for a dependency. Works for all custom git registries, no matter the vendor
func (r *Resolver) findManifestWithGit(repo *git.Repository, head, name, ver string) (pkg.VcpkgManifest, error) {
	// need to cache this, otherwise it will do a git clone per dependency which can be expensive
	headObj, err := repo.CommitObject(plumbing.NewHash(head))
	if err != nil {
		return pkg.VcpkgManifest{}, err
	}
	tree, err := headObj.Tree()
	if err != nil {
		return pkg.VcpkgManifest{}, err
	}
	if ver != "" {
		verPath := "versions/" + name[0:1] + "-/" + name + ".json"
		verFile, err := tree.File(verPath)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to get versions file from vcpkg git tree. %w", err)
		}
		content, err := verFile.Contents()
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to get contents of versions file from vcpkg git tree. %w", err)
		}
		var versions pkg.VcpkgGitVersions 
		err = json.Unmarshal([]byte(content), &versions)
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to unmarshal versions file from vcpkg git tree. %w", err)
		}
		// get tree object sha for the port version
		var gitTreeHash string
		for _, v := range versions.Versions {
			if ver == v.GetFullVersion() {
				gitTreeHash = v.GitTree
				break
			}
		}
		verTree, err := repo.TreeObject(plumbing.NewHash(gitTreeHash))
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to get tree from hash %v. %w", gitTreeHash, err) 
		}
		manFile, err := verTree.File("vcpkg.json")
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to get vcpkg.json file from git tree. %w", err) 
		}
		manContents, err := manFile.Contents()
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to get contents of vcpkg.json file from git tree. %w", err) 
		}
		var resultMan pkg.VcpkgManifest
		json.Unmarshal([]byte(manContents), &resultMan)
		return resultMan, err 
	} else {
		manFile, err := tree.File("ports/" + name + "/vcpkg.json")
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to get vcpkg.json file from ports directory in git tree. %w", err) 
		}
		manContents, err := manFile.Contents()
		if err != nil {
			return pkg.VcpkgManifest{}, fmt.Errorf("failed to get contents of vcpkg.json file from ports directory in git tree. %w", err) 
		}
		var resultMan pkg.VcpkgManifest
		json.Unmarshal([]byte(manContents), &resultMan)
		return resultMan, err 
	}	
}

func (r *Resolver) findManifestForFilesystemReg(path, baseline, name, ver string) (pkg.VcpkgManifest, error) {
	if path == "" {
		return pkg.VcpkgManifest{}, fmt.Errorf("no/empty path specified for vcpkg filesystem registry") 
	}
	var finalVer string 
	if ver == "" {
		baselineBytes, err := os.ReadFile(path + "/versions/baseline.json")
		if err != nil {
			return pkg.VcpkgManifest{}, err
		}
		var baselineGen map[string]any
		err = json.Unmarshal(baselineBytes, &baselineGen)
		if err != nil {
			return pkg.VcpkgManifest{}, err
		}
		var baselineMatch map[string]any
		for k, v := range baselineGen {
			if k == baseline {
				baselineMatch = v.(map[string]any)
				break
			}
		}
		var baselineVer pkg.VcpkgBaselineVersionObject
		for k, v := range baselineMatch {
			if k == name {
				foundBaseline := v.(map[string]any)
				baselineVer = pkg.VcpkgBaselineVersionObject{
					Baseline: foundBaseline["baseline"].(string),
					// default for go json package when unmarshalling number is float64
					PortVersion: foundBaseline["port-version"].(float64),
				}
			}
		}
		if baselineVer.Baseline == "" {
			return pkg.VcpkgManifest{}, fmt.Errorf("Could not find a baseline version for dependency with name %v", name)
		}
		if baselineVer.PortVersion > 0 {
			finalVer = baselineVer.Baseline + "#" + strconv.Itoa(int(baselineVer.PortVersion))
		} else {
			finalVer = baselineVer.Baseline
		}
	} else {
		finalVer = ver
	}
	return getFsManifest(path, name, finalVer)
}

func getFsManifest(path, name, ver string) (pkg.VcpkgManifest, error) {
	versionBytes, err := os.ReadFile(path + "/versions/" + name[0:1] + "-/" + name + ".json")
	var verFileCont pkg.VcpkgFsVersions
	err = json.Unmarshal(versionBytes, &verFileCont)
	if err != nil {
		return pkg.VcpkgManifest{}, err
	}
	for _, v := range verFileCont.Versions {
		if v.GetFullVersion() == ver {
			// the $ character can be used to reference the root of the registry
			manifestPath := strings.ReplaceAll(v.Path, "$", path)
			manBytes, err := os.ReadFile(manifestPath + "/vcpkg.json")
			if err != nil {
				return pkg.VcpkgManifest{}, err
			}

			var vcpkgManRes pkg.VcpkgManifest
			err = json.Unmarshal(manBytes, &vcpkgManRes)
			return vcpkgManRes, nil
		}
	}
	return pkg.VcpkgManifest{}, fmt.Errorf("failed to find vcpkg.json file for dependency name: %v", name)
}

// uses Github API to find the vcpkg.json file for dependency. Good for the default registry since https://github.com/microsoft/vcpkg is a large repo 
// going to remove this because the api rate limit is 60 per hour which I hit quickly scanning large projects
// func (res *Resolver) findManifestWithGhApi(ctx context.Context, baseline, name, ver string) (pkg.VcpkgManifest, error) {
// 	rawRepo := strings.Replace(res.cfg.DefaultRegistry.Repository, "github.com", "raw.githubusercontent.com", 1)
// 	var resultVcpkg pkg.VcpkgManifest
// 	var err error
// 	if ver != "" {
// 		gitTree, err := res.resolveGitTreeSha(ctx, rawRepo, baseline, name, ver)
// 		if err != nil {
// 			return pkg.VcpkgManifest{}, fmt.Errorf("could not find versions json file. head->%v name->%v version->%v. %w", baseline, name, ver, err)
// 		}
// 		blobObjURL, err := res.resolveGitObjectSha(ctx, gitTree)
// 		if err != nil {
// 			return pkg.VcpkgManifest{}, fmt.Errorf("could not find blob URL for port. head->%v name->%v version->%v. %w", baseline, name, ver, err)
// 		}
// 		resultVcpkg, err = res.resolveBlobToManifest(ctx, blobObjURL)
// 		if err != nil {
// 			return resultVcpkg, err
// 		}
// 	} else {
// 		requestURL := rawRepo + "/" + baseline + "/ports/" + name + "/vcpkg.json"
// 		resultVcpkg, err = res.resolveManifest(ctx, requestURL)
// 		if err != nil {
// 			return resultVcpkg, err
// 		}
// 	}
// 	return resultVcpkg, nil
// }

// simply looks up the raw vcpkg.json file at requestURL
// func (res *Resolver) resolveManifest(ctx context.Context, requestURL string) (pkg.VcpkgManifest, error) {
// 	cacheKey := strings.TrimPrefix(strings.TrimPrefix(requestURL, "http://"), "https://")
// 	reader, err := res.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
// 		return getReqToCloser(requestURL, ctx, res.remoteRequestTimeout)
// 	})
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to resolve vcpkg.json %v, %w", requestURL, err)
// 	}
// 	manBytes, err := io.ReadAll(reader) 
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("could not read bytes for vcpkg.json. %w", err)
// 	}
// 	var resultVcpkg pkg.VcpkgManifest
// 	err = json.Unmarshal(manBytes, &resultVcpkg)
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("could not convert vcpkg.json into VcpkgManifest struct. %w", err)
// 	}
//
// 	return resultVcpkg, nil
// }

// Look up blob object and decode the contents. See https://docs.github.com/en/rest/git/blobs?apiVersion=2022-11-28
// func (res *Resolver) resolveBlobToManifest(ctx context.Context, blobObjURL string) (pkg.VcpkgManifest, error) {
// 	cacheKey := strings.TrimPrefix(strings.TrimPrefix(blobObjURL, "http://"), "https://")
// 	reader, err := res.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
// 		return getReqToCloser(blobObjURL, ctx, res.remoteRequestTimeout)
// 	})
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to resolve vcpkg.json blob %v, %w", blobObjURL, err)
// 	}
// 	manBytes, err := io.ReadAll(reader) 
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("could not read bytes for vcpkg.json blob. %w", err)
// 	}
// 	var blobObj pkg.VcpkgBlobObject
// 	err = json.Unmarshal(manBytes, &blobObj)
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("could not convert vcpkg.json into VcpkgBlobObject struct. %w", err)
// 	}
// 	encodedCont := strings.ReplaceAll(blobObj.Content, "\n", "")
// 	decodedCont, err := base64.StdEncoding.DecodeString(encodedCont)
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to decode base64 content to byte array. %w", err)
// 	}
// 	var blobVcpkg pkg.VcpkgManifest
// 	err = json.Unmarshal([]byte(decodedCont), &blobVcpkg)
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to unmarshal byte array to VcpkgManifest struct. %w", err)
// 	}
//
// 	return blobVcpkg, nil
// }


// find blob object sha via api call to github.  
// https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28 
// func (res *Resolver) resolveGitObjectSha(ctx context.Context, gitTree string) (string, error) {
// 	apiRepo := strings.Replace(res.cfg.DefaultRegistry.Repository, "github.com", "api.github.com/repos", 1)
// 	apiTreeReqURL := apiRepo + "/git/trees/" + gitTree
// 	cacheKey := strings.TrimPrefix(strings.TrimPrefix(apiTreeReqURL, "http://"), "https://")
// 	reader, err := res.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
// 		return getReqToCloser(apiTreeReqURL, ctx, res.remoteRequestTimeout)
// 	})
// 	if err != nil {
// 		return "", fmt.Errorf("failed to resolve vcpkg.json %v, %w", apiTreeReqURL, err)
// 	}
// 	atrBytes, err := io.ReadAll(reader) 
// 	if err != nil {
// 		return "", fmt.Errorf("could not read bytes for vcpkg.json. %w", err)
// 	}
// 	var treeObj pkg.VcpkgTreeObject
// 	err = json.Unmarshal(atrBytes, &treeObj)
// 	if err != nil {
// 		return "", fmt.Errorf("could not convert vcpkg.json into VcpkgManifest struct. %w", err)
// 	}
// 	var blobObjUrl string
// 	for _, t := range treeObj.Tree {
// 		if t.Path == "vcpkg.json" {
// 			blobObjUrl = t.Url
// 		}
// 	}
// 	if blobObjUrl == "" {
// 		return "", fmt.Errorf("could not find vcpkg.json blob at tree url. %v", apiTreeReqURL)
// 	}
// 	return blobObjUrl, nil 
// }


// find versions file from registry for port 
// func (res *Resolver) resolveGitTreeSha(ctx context.Context, rawRepo, head, name, ver string) (string, error) {
// 	verReqURL := rawRepo + "/" + head + "/versions/" + name[0:1] + "-/" + name + ".json"
// 	cacheKey := strings.TrimPrefix(strings.TrimPrefix(verReqURL, "http://"), "https://")
// 	reader, err := res.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
// 		return getReqToCloser(verReqURL, ctx, res.remoteRequestTimeout)
// 	})
// 	if err != nil {
// 		return "", fmt.Errorf("failed to resolve vcpkg.json %v, %w", verReqURL, err)
// 	}
// 	if reader, ok := reader.(io.Closer); ok {
// 		defer internal.CloseAndLogError(reader, verReqURL)
// 	}
// 	verBytes, err := io.ReadAll(reader) 
// 	if err != nil {
// 		return "", fmt.Errorf("could not read bytes for vcpkg.json. %w", err)
// 	}
// 	var versions map[string][]pkg.VcpkgGitVersionObject
// 	err = json.Unmarshal(verBytes, &versions)
// 	if err != nil {
// 		return "", fmt.Errorf("could not convert vcpkg.json into VcpkgGitVersionObject struct. %w", err)
// 	}
//
// 	// get tree object sha for the port version
// 	var gitTree string
// 	for _, v := range versions["versions"] {
// 		if ver == v.GetFullVersion() {
// 			gitTree = v.GitTree
// 			break
// 		}
// 	}	
// 	if gitTree == "" {
// 		return "", fmt.Errorf("could not identify a git tree sha for vcpkg.json from url %v. version %v", verReqURL, ver)
// 	}
// 	return gitTree, nil
// }



// func getReqToCloser(requestURL string, ctx context.Context, to time.Duration) (io.ReadCloser, error) {
// 	if requestURL == "" {
// 		return nil, fmt.Errorf("vcpkg request URL cannot be blank")
// 	}
// 	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to create request for vcpkg: %w", err)
// 	}
//
// 	req = req.WithContext(ctx)
//
// 	client := http.Client{
// 		Timeout: to,
// 	}
//
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to get manifest from vcpkg registry %v: %w", requestURL, err)
// 	}
// 	if resp.StatusCode == http.StatusNotFound {
// 		return nil, fmt.Errorf("manifest not found in vcpkg registry at: %v", requestURL)
// 	}
// 	return resp.Body, err
// }

// func (res *Resolver) findManifestForGitReg(repoStr, head, name, ver string) (pkg.VcpkgManifest, error) {
//
// 	roots := cache.GetManager().RootDirs()
// 	_ = roots[0]
// 	repo, err := git.PlainClone(vcpkgCacheKey + "/" + res.cfg.DefaultRegistry.Repository, false, &git.CloneOptions{
// 		URL: repoStr,
// 	})
// 	// reader, err := res.cacheResolveReader(getCacheKeyNameForGitRepo(repoStr, head, name, ver), func() (io.ReadCloser, error) {
// 	// 	if err != nil {
// 	// 		return nil, fmt.Errorf("failed to clone vcpkg repo. %w", err) 
// 	// 	}
// 	// 	return res.findManifestWithGit(repo, head, name, ver)
// 	// })
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to get reader from git clone cache call. %w", err) 
// 	}
// 	commit, err := repo.CommitObject(plumbing.NewHash(head))
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to get reader from git clone cache call. %w", err) 
// 	}
// 	_ = commit.Message
// 	return pkg.VcpkgManifest{}, nil
// 	// return readerToManifest(reader)
// }

// func (res *Resolver) findManifestForBuiltinReg(head, name, ver string, repo *git.Repository) (pkg.VcpkgManifest, error) {
// 	_, err := git.Open(memory.NewStorage(), osfs.New(os.Getenv("VCPKG_ROOT")))
// 	// reader, err := res.cacheResolveReader(getCacheKeyNameForGitRepo(repoStr, head, name, ver), func() (io.ReadCloser, error) {
// 	// 	if err != nil {
// 	// 		return nil, fmt.Errorf("failed to clone vcpkg repo. %w", err) 
// 	// 	}
// 	// 	return res.findManifestWithGit(repo, head, name, ver)
// 	// })
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to get reader from git clone cache call. %w", err) 
// 	}
// 	return pkg.VcpkgManifest{}, nil
// 	// return readerToManifest(reader)
// }

// func readerToManifest(reader io.Reader) (pkg.VcpkgManifest, error) {
// 	manBytes, err := io.ReadAll(reader)
// 	repo, err := git.Init(memory.NewStorage(), nil)
// 	repo.Storer.NewEncodedObject()
// 	if err != nil {
// 		return pkg.VcpkgManifest{}, fmt.Errorf("failed to get bytes from vcpkg manifest reader. %w", err) 
// 	}
// 	var man pkg.VcpkgManifest
// 	err = json.Unmarshal(manBytes, &man)
// 	return man, err
// }

// func getCacheKeyNameForGitRepo(repoStr, head, name, ver string) string {
// 	// helps make the cache path more readable
// 	smplRepo := strings.ReplaceAll(
// 		strings.TrimPrefix(
// 			strings.TrimPrefix(
// 				strings.TrimPrefix(
// 					strings.TrimSuffix(repoStr, ".git"),
// 					"git@",
// 				),
// 				"http://",
// 			),
// 			"https://",
// 		), 
// 		":", 
// 		"/",
// 	)
// 	return smplRepo + "_" + head 
// }



// Copy of cache resolver in java cataloger.
// cacheResolveReader attempts to get a reader from cache, otherwise caches the contents of the resolve() function.
// this function is guaranteed to return an unread reader for the correct contents.
// NOTE: this could be promoted to the internal cache package as a specialized version of the cache.Resolver
// if there are more users of this functionality
// func (res *Resolver) cacheResolveReader(key string, resolve func() (io.ReadCloser, error)) (io.Reader, error) {
// 	reader, err := res.cache.Read(key)
// 	if err == nil && reader != nil {
// 		return reader, err
// 	}
//
// 	contentReader, err := resolve()
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer internal.CloseAndLogError(contentReader, key)
//
// 	// store the contents to return a new reader with the same content
// 	contents, err := io.ReadAll(contentReader)
// 	if err != nil {
// 		return nil, err
// 	}
// 	err = res.cache.Write(key, bytes.NewBuffer(contents))
// 	return bytes.NewBuffer(contents), err
// }
