package pkg

import (
	"strconv"
	"strings"
)

type VcpkgRegistryKind string

const (
	FileSystem VcpkgRegistryKind = "filesystem"
	Git        VcpkgRegistryKind = "git"
	// is just a locally cloned Git repository
	Builtin    VcpkgRegistryKind = "builtin"
)

// represents contents of "vcpkg-configuration.json"
type VcpkgConfig struct {
	DefaultRegistry VcpkgRegistry   `json:"default-registry"`
	OverlayPorts    []string        `json:"overlay-ports,omitempty"`
	OverlayTriplets []string        `json:"overlay-triplets,omitempty"`
	Registries      []VcpkgRegistry `json:"registries,omitempty"`
}

type VcpkgRegistry struct {
	Baseline   string            `json:"baseline,omitempty"`
	Kind       VcpkgRegistryKind `json:"kind"`
	Packages   []string            `json:"packages,omitempty"`
	Path       string            `json:"path,omitempty"`
	Reference  string            `json:"reference,omitempty"`
	Repository string            `json:"repository,omitempty"`
}

// represents contents of "vcpkg.json" file. (a.k.a the manifest file)
type VcpkgManifest struct {
	BuiltinBaseline string                  `json:"builtin-baseline,omitempty"`
	DefaultFeatures  []any    		`json:"default-features,omitempty"`
	// string or []VcpkgDependency
	Dependencies    []any           `json:"dependencies,omitempty"`
	// string or []string
	Description     any             `json:"description,omitempty"`
	Documentation   string                  `json:"documentation,omitempty"`
	Features        map[string]VcpkgFeature `json:"features,omitempty"`
	Homepage        string                  `json:"homepage,omitempty"`
	// In SPDX license expression format. see https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json
	License     string          `json:"license,omitempty"`
	Maintainers []string        `json:"maintainers,omitempty"`
	Name        string          `json:"name,omitempty"`
	Overrides   []VcpkgOverride `json:"overrides,omitempty"`
	PortVersion int             `json:"port-version,omitempty"`
	Supports    string          `json:"supports,omitempty"`
	// at most one of these version fields will be present and represent different versioning strategies
	// see https://learn.microsoft.com/en-us/vcpkg/users/versioning#version-schemes for more details
	Version       string `json:"version,omitempty"`
	VersionSemver string `json:"version-semver,omitempty"`
	VersionDate   string `json:"version-date,omitempty"`
	VersionString string `json:"version-string,omitempty"`
}

// VcpkgDependency represents a single entry in the dependencies section of the "vcpkg.json" source
type VcpkgDependency struct {
	DefaultFeatures bool                 `json:"default-features,omitempty"`
	Features        []VcpkgFeatureObject `json:"features,omitempty"`
	Host            bool                 `json:"host,omitempty"`
	Name            string               `json:"name"`
	// A "Platform Expression" that limits the platforms where the feature is required. Optional
	Platform   string `json:"platform,omitempty"`
	VersionGte string `json:"version>=,omitempty"`
}

// Confusingly not the same as Feature Object
// see https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json#feature vs https://learn.microsoft.com/en-us/vcpkg/reference/vcpkg-json#feature-object
type VcpkgFeature struct {
	Description  string            `json:"description"`
	Dependencies []any `json:"dependencies,omitempty"`
	// "Platform expression"
	Supports string `json:"supports,omitempty"`
	// SPDX license expression
	License string `json:"license,omitempty"`
}

type VcpkgFeatureObject struct {
	Name     string `json:"name"`
	Platform string `json:"platform,omitempty"`
}

type VcpkgOverride struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	PortVersion int    `json:"port-version,omitempty"`
}

func (v VcpkgManifest) GetFullVersion() string {
	return getFullVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString, v.PortVersion)
}

func (v VcpkgGitVersionObject) GetFullVersion() string {
	return getFullVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString, v.PortVersion)
}

func (v VcpkgFsVersionObject) GetFullVersion() string {
	return getFullVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString, v.PortVersion)
}

func (v VcpkgGitVersionObject) GetPopulatedVersion() string {
	return getPopulatedVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString)
}

func (v VcpkgFsVersionObject) GetPopulatedVersion() string {
	return getPopulatedVersionName(v.Version, v.VersionSemver, v.VersionDate, v.VersionString)
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

func getFullVersionName(version, versionSemver, versionDate, versionString string, portVersion int) string {
	if version != "" && portVersion != 0 {
		vElems := []string{version, "#", strconv.Itoa(portVersion)}
		return strings.Join(vElems, "")
	} else if version != "" {
		return version
	} else if versionSemver != "" && portVersion != 0 {
		vElems := []string{versionSemver, "#", strconv.Itoa(portVersion)}
		return strings.Join(vElems, "")
	} else if versionSemver != "" {
		return versionSemver
	} else if versionDate != "" && portVersion != 0 {
		vElems := []string{versionDate, "#", strconv.Itoa(portVersion)}
		return strings.Join(vElems, "")
	} else if versionDate != "" {
		return versionDate
	} else if versionString != "" && portVersion != 0 {
		vElems := []string{versionString, "#", strconv.Itoa(portVersion)}
		return strings.Join(vElems, "")
	} else if versionString != "" {
		return versionString
	} else {
		return ""
	}
}

// used to get specific dependency from git history
type VcpkgGitVersionObject struct {
	// Sha1 value used to retrieve specific git tree object from Github. https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28
	GitTree     string `json:"git-tree"`
	Version     string `json:"version,omitempty"`
	VersionSemver string `json:"version-semver,omitempty"`
	VersionDate   string `json:"version-date,omitempty"`
	VersionString string `json:"version-string,omitempty"`
	PortVersion int    `json:"port-version"`
}

// Filesystem VersionObject 
type VcpkgFsVersionObject struct {
	Path     string `json:"path"`
	Version       string `json:"version,omitempty"`
	VersionSemver string `json:"version-semver,omitempty"`
	VersionDate   string `json:"version-date,omitempty"`
	VersionString string `json:"version-string,omitempty"`
	PortVersion int    `json:"port-version"`
}

type VcpkgFsVersions struct {
	Versions []VcpkgFsVersionObject `json:"versions"`
}

// Git tree object from gh api
type VcpkgTreeObject struct {
	Sha       string `json:"sha"`
	Url       string
	Tree      []VcpkgTreeNode `json:"tree"`
	Truncated bool            `json:"truncated"`
}

// Git blob object from gh api
type VcpkgBlobObject struct {
	Sha      string `json:"sha"`
	NodeId   string `json:"node_id"`
	Size     int    `json:"size"`
	Content  string `json:"content"`
	Encoding string `json:"base64"`
}

// Tree node from gh api with info on object it represents
type VcpkgTreeNode struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	Sha  string `json:"sha"`
	Size int    `json:"size"`
	Url  string `json:"url"`
}

// represents whats found in vcpkg-lock.json. json keys are unknown until build 
type VcpkgLockRecord struct {
	Repo string
	Head string
}

type VcpkgBaselineVersionObject struct {
	Baseline string `json:"baseline"`
	PortVersion int `json:"port-version"`
}
