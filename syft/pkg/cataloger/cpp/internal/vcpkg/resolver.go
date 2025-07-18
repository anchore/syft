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
	allowGitClone		 bool
	cfg                  pkg.VcpkgConfig
	resolved             map[ID]*pkg.VcpkgManifest
}

// NewResolver constructs a new Resolver with the given vcpkg configuration.
func NewResolver(cfg pkg.VcpkgConfig, allowGitClone bool) *Resolver {
	return &Resolver{
		allowGitClone:		  allowGitClone,
		cfg:                  cfg,
		resolved:             map[ID]*pkg.VcpkgManifest{},
	}
}

func getBuiltinRepo(repo string, allowGitClone bool) (*git.Repository, error) {
	path := os.Getenv("VCPKG_ROOT")
	if path == "" {
		cachePath, err := getCachePath(vcpkgRepo)
		if err != nil {
			return nil, err
		}
		return getRepo(repo, cachePath, allowGitClone)
	}
	return getRepo(repo, path, allowGitClone)
}

func getRepo(repo, path string, allowGitClone bool) (*git.Repository, error) {
	// needed in case it's a private custom git registry
	// sshPath := os.Getenv("HOME") + "/.ssh/gitlab"
	// publicKeys, err := ssh.NewPublicKeysFromFile("git", sshPath, "")
	r, err := git.PlainOpen(path)
	if err != nil {
		if allowGitClone {
			r, err = git.PlainClone(path, false, &git.CloneOptions{
				URL: repo,
			})
			if err != nil {
				return nil, fmt.Errorf("Could not clone repo %v.", repo)
			}
		} else {
			return nil, fmt.Errorf(`Cannot find a local repo at %v. To clone repo %v, vcpkg-allow-git-clone must be enabled in the configuration`, path, repo)
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
			gitRepo, err = getBuiltinRepo(vcpkgRepo, r.allowGitClone)
		} else {
			cachePath, err := getCachePath(reg.Repository)
			if err != nil {
				return nil, err
			}
			gitRepo, err = getRepo(reg.Repository, cachePath, r.allowGitClone)
		}
		vcpkg, err = r.findManifestWithGit(gitRepo, reg.Baseline, name, version)
		if err != nil {
			return nil, err 
		}
		id := ID{reg.Repository, reg.Baseline, name, version}
		r.resolved[id] = &vcpkg
	case pkg.Builtin:
		gitRepo, err := getBuiltinRepo(vcpkgRepo, r.allowGitClone)
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

func (r *Resolver) findManifestWithGit(repo *git.Repository, head, name, ver string) (pkg.VcpkgManifest, error) {
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

