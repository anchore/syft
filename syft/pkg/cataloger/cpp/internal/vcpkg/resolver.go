package vcpkg

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const defaultRepo = "https://github.com/microsoft/vcpkg"

// this is the default registry for vcpkg. it is the default "builtin" registry if a builtin one isn't specified 
var defaultRegistry = pkg.VcpkgRegistryEntry{
	Baseline: "master",
	Kind: pkg.Git,
	Repository: defaultRepo,
}

// represents contents of "vcpkg.json" file. (a.k.a the manifest file)
type Vcpkg struct {
	BuiltinBaseline string                  `json:"builtin-baseline,omitempty"`
	DefaultFeatures  []any    		`json:"default-features,omitempty"`
	// string or []VcpkgDependency
	Dependencies    []any           `json:"dependencies,omitempty"`
	// string or []string
	Description     any             `json:"description,omitempty"`
	Documentation   string                  `json:"documentation,omitempty"`
	Features        map[string]vcpkgFeatureEntry `json:"features,omitempty"`
	Homepage        string                  `json:"homepage,omitempty"`
	// In SPDX license expression format. see https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json
	License     string          `json:"license,omitempty"`
	Maintainers []string        `json:"maintainers,omitempty"`
	Name        string          `json:"name,omitempty"`
	// Only overrides defined by the top-level project are used
	Overrides   []vcpkgOverrideEntry `json:"overrides,omitempty"`
	PortVersion float64             `json:"port-version,omitempty"`
	Supports    string          `json:"supports,omitempty"`
	// at most one of these version fields will be present and represent different versioning strategies
	// see https://learn.microsoft.com/en-us/vcpkg/users/versioning#version-schemes for more details
	Version       string `json:"version,omitempty"`
	VersionSemver string `json:"version-semver,omitempty"`
	VersionDate   string `json:"version-date,omitempty"`
	VersionString string `json:"version-string,omitempty"`
}

// Confusingly not the same as Feature Object
// see https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json#feature vs https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json#feature-object
type vcpkgFeatureEntry struct {
	Description  string            `json:"description"`
	// string or []VcpkgDependency
	Dependencies []any `json:"dependencies,omitempty"`
	// "Platform expression"
	Supports string `json:"supports,omitempty"`
	// SPDX license expression
	License string `json:"license,omitempty"`
}

type vcpkgOverrideEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	VersionSemver string `json:"version-semver,omitempty"`
	VersionDate   string `json:"version-date,omitempty"`
	VersionString string `json:"version-string,omitempty"`
	PortVersion float64    `json:"port-version,omitempty"`
	
}

// represents contents of "vcpkg-configuration.json" file
type VcpkgConfig struct {
	DefaultRegistry *pkg.VcpkgRegistryEntry   `json:"default-registry"`
	OverlayPorts    []string        `json:"overlay-ports,omitempty"`
	OverlayTriplets []string        `json:"overlay-triplets,omitempty"`
	Registries      []pkg.VcpkgRegistryEntry `json:"registries,omitempty"`
}

// used to get specific dependency from git history
type vcpkgGitVersionObjectEntry struct {
	// Sha1 value used to retrieve specific git tree object from Github. https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28
	GitTree       string `json:"git-tree"`
	Version       string `json:"version,omitempty"`
	VersionSemver string `json:"version-semver,omitempty"`
	VersionDate   string `json:"version-date,omitempty"`
	VersionString string `json:"version-string,omitempty"`
	PortVersion   float64   `json:"port-version"`
}

// represents versions file "<name-of-dependency>.json" found in versions folder
type vcpkgGitVersions struct {
	Versions []vcpkgGitVersionObjectEntry `json:"versions"`
}

// vcpkgDependencyEntry represents a single entry in the dependencies section of the "vcpkg.json" source
type vcpkgDependencyEntry struct {
	DefaultFeatures bool                 `json:"default-features,omitempty"`
	Features        []vcpkgFeatureObjectEntry `json:"features,omitempty"`
	Host            bool                 `json:"host,omitempty"`
	Name            string               `json:"name"`
	// A "Platform Expression" that limits the platforms where the feature is required. Optional
	Platform   string `json:"platform,omitempty"`
	VersionGte string `json:"version>=,omitempty"`
}

type vcpkgFeatureObjectEntry struct {
	Name     string `json:"name"`
	Platform string `json:"platform,omitempty"`
}

// Filesystem VersionObject 
type vcpkgFsVersionObjectEntry struct {
	Path     string `json:"path"`
	Version       string `json:"version,omitempty"`
	VersionSemver string `json:"version-semver,omitempty"`
	VersionDate   string `json:"version-date,omitempty"`
	VersionString string `json:"version-string,omitempty"`
	PortVersion float64    `json:"port-version"`
}

// represents filesystem versions file "<name-of-dependency>.json" found in versions folder
type vcpkgFsVersions struct {
	Versions []vcpkgFsVersionObjectEntry `json:"versions"`
}

// helpful to define relationships between Vcpkgs
type manifestNode struct {
	Parent *pkg.VcpkgManifest
	Child *pkg.VcpkgManifest 
}

type vcpkgBaselineVersionObjectEntry struct {
	Baseline string `json:"baseline"`
	PortVersion float64 `json:"port-version"`
}

func (v *Vcpkg) GetFullVersion() string {
	return getFullVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString, v.PortVersion)
}

func (v *vcpkgGitVersionObjectEntry) GetFullVersion() string {
	return getFullVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString, v.PortVersion)
}

func (v *vcpkgFsVersionObjectEntry) GetFullVersion() string {
	return getFullVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString, v.PortVersion)
}

func (v *vcpkgGitVersionObjectEntry) GetPopulatedVersion() string {
	return getPopulatedVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString)
}

func (v *vcpkgFsVersionObjectEntry) GetPopulatedVersion() string {
	return getPopulatedVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString)
}

func (v *vcpkgOverrideEntry) GetFullVersion() string {
	return getFullVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString, v.PortVersion)
}

func getPopulatedVersionName(version, versionSemver, versionDate, versionString string) string {
	if version != "" {
		return version
	} else if versionSemver != "" {
		return versionSemver
	} else if versionDate != "" {
		return versionDate
	} else if versionString != "" {
		return versionString
	} else {
		return ""
	}
}

func getFullVersionName(version, versionSemver, versionDate, versionString string, portVersion float64) string {
	if version != "" && portVersion != 0 {
		vElems := []string{version, "#", strconv.Itoa(int(portVersion))}
		return strings.Join(vElems, "")
	} else if version != "" {
		return version
	} else if versionSemver != "" && portVersion != 0 {
		vElems := []string{versionSemver, "#", strconv.Itoa(int(portVersion))}
		return strings.Join(vElems, "")
	} else if versionSemver != "" {
		return versionSemver
	} else if versionDate != "" && portVersion != 0 {
		vElems := []string{versionDate, "#", strconv.Itoa(int(portVersion))}
		return strings.Join(vElems, "")
	} else if versionDate != "" {
		return versionDate
	} else if versionString != "" && portVersion != 0 {
		vElems := []string{versionString, "#", strconv.Itoa(int(portVersion))}
		return strings.Join(vElems, "")
	} else if versionString != "" {
		return versionString
	} else {
		return ""
	}
}

// represents whats found in vcpkg-lock.json. json keys are unknown until build 
type VcpkgLock struct {
	Records []VcpkgLockEntry
}

type VcpkgLockEntry struct {
	Repo string
	Head string
}

const vcpkgRepo string = "https://github.com/microsoft/vcpkg"
const vcpkgCacheKey string = "cpp/vcpkg/repo/v1"

type ID struct {
	location string
	head string
	name    string
	version string
}

// Resolver is a short-lived utility to resolve vcpkg manifests from multiple sources, including:
// the filesystem, local maven cache directories, remote maven repositories, and the syft cache
type Resolver struct {
	allowGitClone		 bool
	cfg                  *VcpkgConfig
	resolved             map[ID]*pkg.VcpkgManifest
}

// NewResolver constructs a new Resolver with the given vcpkg configuration.
func NewResolver(cfg *VcpkgConfig, allowGitClone bool) *Resolver {
	return &Resolver{
		allowGitClone:		  allowGitClone,
		cfg:                  cfg,
		resolved:             map[ID]*pkg.VcpkgManifest{},
	}
}

// Get all of the manifest/vcpkg.json files for a vcpkg dependency 
func (r *Resolver) FindManifests(dependency any, df bool, triplet, currentPath, builtinBaseline string, overrides []vcpkgOverrideEntry, parent *pkg.VcpkgManifest) ([]manifestNode, error) {
	var name string
	var fullVersion string
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
			fullVersion = d["version>="].(string)
		}
		if d["default-features"] != nil {
			defaultFeatures = defaultFeatures && d["default-features"].(bool)
		}
		if d["features"] != nil {
			features = d["features"].([]any)
		}
	}
	// for when top-level manifest has this dependency version overriden 
	if over, ok := depVerOverriden(name, overrides); ok {
		fullVersion = over.Version
	}
	reg := r.depRegistry(name, builtinBaseline)
	vcpkg, err := r.findManifestFromReg(reg, currentPath, name, fullVersion)
	if err != nil {
		return nil, err 
	}
	// need to add dependency to map, even if it doesn't find its manifest, to avoid infinite loops caused by circular depenencies
	switch reg.Kind {
	case pkg.Git:
		id := ID{reg.Repository, reg.Baseline, name, fullVersion}
		r.resolved[id] = vcpkg.BuildManifest(reg, triplet)
	case pkg.Builtin:
		vcpkgRoot := os.Getenv("VCPKG_ROOT")
		id := ID{vcpkgRoot, reg.Baseline, name, fullVersion}
		r.resolved[id] = vcpkg.BuildManifest(reg, triplet)
	case pkg.FileSystem:
		id := ID{reg.Path, reg.Baseline, name, fullVersion}
		r.resolved[id] = vcpkg.BuildManifest(reg, triplet)
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
		case vcpkgFeatureObjectEntry:
			for name, f := range vcpkg.Features {
				if fo.Name == name || (defaultFeatures && isDefaultFeature(name, vcpkg.DefaultFeatures)) {
					vcpkg.Dependencies = append(vcpkg.Dependencies, f.Dependencies...)
				}
			}
		}
	}
	
	childManifest := vcpkg.BuildManifest(reg, triplet)
	manNodes := []manifestNode{}
	manNodes = append(manNodes, manifestNode{
		Parent: parent,
		Child: childManifest,
	})
	if len(vcpkg.Dependencies) != 0 {
		for _, dep := range vcpkg.Dependencies {
			resolvedManifest, ok := r.depResolved(dep, builtinBaseline)
			if ok {
				// this is to catch duplicates 
				manNodes = append(manNodes, manifestNode{
					// child is parent in this case
					Parent: childManifest,
					Child: resolvedManifest,
				})
			} else {
				childManNodes, err := r.FindManifests(dep, df, triplet, currentPath, builtinBaseline, overrides, childManifest)
				if err != nil {
					return nil, fmt.Errorf("could not find vcpkg.json file for dependency. %w", err)
				}
				manNodes = append(manNodes, childManNodes...)
			}
		}
	}
	return manNodes, nil
}

func depVerOverriden(name string, overrides []vcpkgOverrideEntry) (*vcpkgOverrideEntry, bool)  {
	for _, over := range overrides {
		if over.Name == name {
			return &over, true
		}
	}
	return nil, false
}

func getRepo(repo, path string, allowGitClone bool) (*git.Repository, string, error) {
	// detect root directory, helps with testing
	r, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil || r == nil {
		vcpkgCachePath, err := getVcpkgGitCachePath()
		if err != nil {
			return nil, vcpkgCachePath, fmt.Errorf("Could not get vcpkg cache path. %w", err)
		}
		vr, err := git.PlainOpen(vcpkgCachePath)
		if err != nil || vr == nil {
			if allowGitClone {
				r, err = git.PlainClone(path, false, &git.CloneOptions{
					URL: repo,
				})
				if err != nil {
					return nil, path, fmt.Errorf("Could not clone repo %v.", repo)
				}
			} else {
				log.Errorf(`Could not find local repo at %v. To clone repo %v, vcpkg-allow-git-clone must be enabled`, path, repo)
				return nil, vcpkgCachePath, fmt.Errorf(`Could not find local repo at %v. To clone repo %v, vcpkg-allow-git-clone must be enabled`, path, repo)
			}
		} else {
			return vr, vcpkgCachePath, err
		}
	}
	return r, path, nil
}

// determine location in syft cache to store repo if it needs to be cloned
func getSyftVcpkgCachePath(repo string) (string, error) {
	trimmedRepo := strings.TrimPrefix(strings.TrimPrefix(repo, "http://"), "https://")
	roots := cache.GetManager().RootDirs()
	if len(roots) == 0 {
		return "", fmt.Errorf("could not determine cache root")
	}
	return roots[0] + "/" + vcpkgCacheKey + "/" + trimmedRepo, nil
}

// get path of vcpkg cache
func getVcpkgGitCachePath() (string, error) {
	roots := cache.GetManager().RootDirs()
	if len(roots) == 0 {
		return "", fmt.Errorf("could not determine cache root")
	}
	// not sure if this is an exceptible way of getting the vcpkg cache directory
	return roots[0] + "/../vcpkg/registries/git", nil
}


// determines which registry to use by the name of the dependency
func (r *Resolver) depRegistry(name string, builtinBaseline string) *pkg.VcpkgRegistryEntry {
	var reg *pkg.VcpkgRegistryEntry
	if r.cfg != nil {
		for _, res := range r.cfg.Registries {
			if slices.Contains(res.Packages, name) {
				reg = &res
			}
		}
		if r.cfg.DefaultRegistry != nil && reg == nil {
			reg = r.cfg.DefaultRegistry
		}
	}
	if reg == nil {
		reg = &defaultRegistry
		reg.Baseline = builtinBaseline
	} else if reg.Kind == pkg.Builtin {
		reg.Baseline = builtinBaseline
	}
	return reg 
}

// checks if dependency has been retrieved already this run. Without this check, there were infinite loops from circular dependencies 
func (r *Resolver) depResolved(dep any, builtinBaseline string) (*pkg.VcpkgManifest, bool) {
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
	reg := r.depRegistry(name, builtinBaseline)
	var location string
	if reg.Repository != "" {
		location = reg.Repository
	} else if reg.Path != "" {
		location = reg.Path
	} else {
		location = vcpkgRepo
	}
	resolved, ok := r.resolved[ID{location, reg.Baseline, name, version}]
	return resolved, ok
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

func (r *Resolver) findManifestFromReg(reg *pkg.VcpkgRegistryEntry, currentPath, name, fullVersion string) (*Vcpkg, error) {
	if reg == nil {
		return nil, fmt.Errorf("no vcpkg registry found which is required.")
	}
	switch reg.Kind {
	case pkg.Git:
		if reg.Repository == "" {	
			return nil, fmt.Errorf("No repo found for vcpkg git registry")
		}
		if strings.TrimSuffix(reg.Repository, ".git") == vcpkgRepo {
			path := os.Getenv("VCPKG_ROOT")
			gitRepo, path, err := getRepo(vcpkgRepo, path, r.allowGitClone)
			if err != nil {
				return nil, err
			}
			vcpkg, err := r.getManifestFromGitRepo(gitRepo, currentPath, path, reg.Baseline, name, fullVersion)
			if err != nil {
				return nil, err 
			}
			return vcpkg, err
		} else {
			cachePath, err := getSyftVcpkgCachePath(reg.Repository)
			if err != nil {
				return nil, err
			}
			gitRepo, cachePath, err := getRepo(reg.Repository, cachePath, r.allowGitClone)
			if err != nil {
				return nil, err
			}
			vcpkg, err := r.getManifestFromGitRepo(gitRepo, currentPath, cachePath, reg.Baseline, name, fullVersion)
			if err != nil {
				return nil, err 
			}
			return vcpkg, err
		}
	case pkg.Builtin:
		path := os.Getenv("VCPKG_ROOT")
		gitRepo, path, err := getRepo(vcpkgRepo, path, r.allowGitClone)
		if err != nil {
			return nil, err
		}
		vcpkg, err := r.getManifestFromGitRepo(gitRepo, currentPath, path, reg.Baseline, name, fullVersion)
		if err != nil {
			return nil, err 
		}
		return vcpkg, err
	case pkg.FileSystem:
		if reg.Path == "" {
			return nil, fmt.Errorf("No path found for vcpkg filesystem registry.")
		}
		baseline := reg.Baseline 
		if baseline == "" {
			baseline = "default"
		}
		vcpkg, err := r.getManifestFromFilesystem(reg.Path, baseline, name, fullVersion)
		if err != nil {
			return nil, err 
		}
		return vcpkg, err
	default:
		return nil, fmt.Errorf("vcpkg registry has no kind which is required.")
	}
}

// locates and gets the manifest file via the go-git 
func (r *Resolver) getManifestFromGitRepo(repo *git.Repository, currentPath, repoPath, head, name, fullVersion string) (*Vcpkg, error) {
	wt, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	headObj, err := repo.CommitObject(plumbing.NewHash(head))
	if err != nil {
		return nil, err
	}
	tree, err := headObj.Tree()
	if err != nil {
		return nil, err
	}
	if fullVersion != "" {
		verPath := "versions/" + name[0:1] + "-/" + name + ".json"
		verFile, err := findFileInTree(currentPath, wt.Filesystem.Root(), repoPath, verPath, tree)
		if err != nil {
			return nil, fmt.Errorf("failed to get versions file from vcpkg git tree. %w", err)
		}
		content, err := verFile.Contents()
		if err != nil {
			return nil, fmt.Errorf("failed to get contents of versions file from vcpkg git tree. %w", err)
		}
		var versions vcpkgGitVersions 
		err = json.Unmarshal([]byte(content), &versions)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal versions file from vcpkg git tree. %w", err)
		}
		// get tree object sha for the port version
		var gitTreeHash string
		for _, v := range versions.Versions {
			if fullVersion == v.GetFullVersion() {
				gitTreeHash = v.GitTree
				break
			}
		}
		verTree, err := repo.TreeObject(plumbing.NewHash(gitTreeHash))
		if err != nil {
			return nil, fmt.Errorf("failed to get tree from hash %v. %w", gitTreeHash, err) 
		}
		manFile, err := verTree.File("vcpkg.json")
		if err != nil {
			return nil, fmt.Errorf("failed to get vcpkg.json file from git tree. %w", err) 
		}
		manContents, err := manFile.Contents()
		if err != nil {
			return nil, fmt.Errorf("failed to get contents of vcpkg.json file from git tree. %w", err) 
		}
		var resultMan Vcpkg
		json.Unmarshal([]byte(manContents), &resultMan)
		return &resultMan, err 
	} else {
		portPath := "ports/" + name + "/vcpkg.json"
		manFile, err := findFileInTree(currentPath, wt.Filesystem.Root(), repoPath, portPath, tree)
		if err != nil {
			return nil, fmt.Errorf("failed to get vcpkg.json file from ports directory in git tree. %w", err) 
		}
		manContents, err := manFile.Contents()
		if err != nil {
			return nil, fmt.Errorf("failed to get contents of vcpkg.json file from ports directory in git tree. %w", err) 
		}
		var resultMan Vcpkg
		json.Unmarshal([]byte(manContents), &resultMan)
		return &resultMan, err 
	}	
}

func findFileInTree(currentPath, rootPath, repoPath, filePath string, tree *object.Tree) (*object.File, error) {
	verFile, err := tree.File(filePath)
	if err != nil {
		// Construct correct path relative to git root
		// example from tests current $HOME/syft/syft/pkg/cataloger/cpp, root $HOME/syft, reg test-fixtures/vcpkg-registry
		// this case is most likely only relevant to testing 
		splitPaths := strings.Split(currentPath, rootPath + "/")
		if len(splitPaths) > 1 {
			verFile, err = tree.File(splitPaths[1] + "/" + repoPath + "/" + filePath) 
		}
	}
	return verFile, err
}

// locates and gets the manifest file via the filesystem path 
func (r *Resolver) getManifestFromFilesystem(path, baseline, name, fullVersion string) (*Vcpkg, error) {
	if path == "" {
		return &Vcpkg{}, fmt.Errorf("no/empty path specified for vcpkg filesystem registry") 
	}
	var finalVer string 
	if fullVersion == "" {
		baselineBytes, err := os.ReadFile(path + "/versions/baseline.json")
		if err != nil {
			return &Vcpkg{}, err
		}
		var baselineGen map[string]any
		err = json.Unmarshal(baselineBytes, &baselineGen)
		if err != nil {
			return &Vcpkg{}, err
		}
		var baselineMatch map[string]any
		for k, v := range baselineGen {
			if k == baseline {
				baselineMatch = v.(map[string]any)
				break
			}
		}
		var baselineVer vcpkgBaselineVersionObjectEntry
		for k, v := range baselineMatch {
			if k == name {
				foundBaseline := v.(map[string]any)
				baselineVer = vcpkgBaselineVersionObjectEntry{
					Baseline: foundBaseline["baseline"].(string),
					// default for go json package when unmarshalling number is float64
					PortVersion: foundBaseline["port-version"].(float64),
				}
			}
		}
		if baselineVer.Baseline == "" {
			return nil, fmt.Errorf("Could not find a baseline version for dependency with name %v", name)
		}
		if baselineVer.PortVersion > 0 {
			finalVer = baselineVer.Baseline + "#" + strconv.Itoa(int(baselineVer.PortVersion))
		} else {
			finalVer = baselineVer.Baseline
		}
	} else {
		finalVer = fullVersion
	}
	return getFsManifest(path, name, finalVer)
}

// retrieves manifest file from the filesystem
func getFsManifest(path, name, ver string) (*Vcpkg, error) {
	versionBytes, err := os.ReadFile(path + "/versions/" + name[0:1] + "-/" + name + ".json")
	var verFileCont vcpkgFsVersions
	err = json.Unmarshal(versionBytes, &verFileCont)
	if err != nil {
		return nil, err
	}
	for _, v := range verFileCont.Versions {
		if v.GetFullVersion() == ver {
			// the $ character can be used to reference the root of the registry
			manifestPath := strings.ReplaceAll(v.Path, "$", path)
			manBytes, err := os.ReadFile(manifestPath + "/vcpkg.json")
			if err != nil {
				return nil, err
			}

			var vcpkgManRes Vcpkg
			err = json.Unmarshal(manBytes, &vcpkgManRes)
			return &vcpkgManRes, nil
		}
	}
	return nil, fmt.Errorf("failed to find vcpkg.json file for dependency name: %v", name)
}

func (v *Vcpkg) BuildManifest(reg *pkg.VcpkgRegistryEntry, triplet string) *pkg.VcpkgManifest {
	var desc []string
	switch d := v.Description.(type) {
	case string:
		desc = append(desc, d)
	case []string:
		desc = append(desc, d...)
	}
	return &pkg.VcpkgManifest{
		Description: desc,
		Documentation: v.Documentation,
		FullVersion: v.GetFullVersion(),
		License: v.License,
		Maintainers: v.Maintainers,
		Name: v.Name,
		Supports: v.Supports,
		Registry: reg,
		Triplet: triplet,
	}
}
