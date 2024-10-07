package cargo

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// For JSON naming purposes, it is important, that the name stays the same here!

type LockEntry struct {
	pkg.RustCargoLockEntry
	*RegistryInfo
	*CrateInfo
	Licenses pkg.LicenseSet
}

type LockEntryHydrator struct {
	crate    crateResolver
	registry registryResolver
}

func NewLockEntryHydrator(onlineEnabled bool) LockEntryHydrator {
	return LockEntryHydrator{
		crate:    newCrateResolver(onlineEnabled),
		registry: newRegistryResolver(onlineEnabled),
	}
}

func (r *LockEntryHydrator) hydrateLockEntry(entry *LockEntry, lockVersion int) error { // nolint:unparam  // known-unknowns will need to return an error
	entry.Licenses = pkg.NewLicenseSet()
	entry.RustCargoLockEntry.CargoLockVersion = lockVersion

	reg, err := r.registry.resolve(*entry)
	if err == nil {
		entry.RegistryInfo = &reg
	}

	cra, err := r.crate.resolve(*entry)

	if err == nil {
		entry.CrateInfo = &cra
		for _, license := range cra.Licenses {
			if entry.CrateInfo.DownloadLink != "" && license != "" {
				entry.Licenses.Add(pkg.NewLicenseFromURLs(license, entry.CrateInfo.DownloadLink))
			}
		}
	} else {
		// TODO: return known-unknown error
		log.WithFields("pkg", fmt.Sprintf("%s@%s", entry.Name, entry.Version)).Tracef("unable to resolve rust cargo lock info remotely: %s", err)
	}

	return nil
}

func (r *LockEntry) sourceID() *sourceID {
	if r.Source == "" {
		//Todo: add handling for looking in the current workspace, finding all Cargo.toml's and checking if any matches.
		//		if a match is found license information could potentially still be added.
		//	 	In that scenario adding "path" or "directory" support might make sense.
		return nil
	}
	var before, after, found = strings.Cut(r.Source, "+")
	if !found {
		return nil
	}

	return &sourceID{
		kind: before,
		url:  after,
	}
}

func (r *LockEntry) cargoArchiveDownloadLink() (string, bool) {
	if r.RegistryInfo == nil {
		return "", false
	}

	url := r.RegistryInfo.Download

	if !strings.Contains(url, crate) &&
		!strings.Contains(url, version) &&
		!strings.Contains(url, prefix) &&
		!strings.Contains(url, lowerPrefix) &&
		!strings.Contains(url, sha256Checksum) {
		return fmt.Sprintf("%s/%s/%s/download", url, r.Name, r.Version), r.RegistryInfo.IsLocalFile
	}

	// TODO: can we simply craft the URL instead of replacing placeholders?
	var link = url
	link = strings.ReplaceAll(link, crate, r.Name)
	link = strings.ReplaceAll(link, version, r.Version)
	link = strings.ReplaceAll(link, prefix, r.getPrefix())
	link = strings.ReplaceAll(link, lowerPrefix, strings.ToLower(r.getPrefix()))
	link = strings.ReplaceAll(link, sha256Checksum, r.Checksum)
	return link, r.RegistryInfo.IsLocalFile
}

// getPrefix get {path} for https://doc.rust-lang.org/cargo/reference/registry-index.html
func (r *LockEntry) getPrefix() string {
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

// Todo: Do we care about any metadata present in the rust repository index?
//
// type DependencyInformation struct {
//	Name          string                            `json:"name"`
//	Version       string                            `json:"vers"`
//	Dependencies  []DependencyDependencyInformation `json:"deps"`
//	Checksum      string                            `json:"cksum"`
//	Features      map[string]string                 `json:"features"`
//	Yanked        bool                              `json:"yanked"`
//	Links         string                            `json:"links"`
//	StructVersion int                               `json:"v"`
//	Features2     map[string]string                 `json:"features2"`
//	RustVersion   string                            `json:"rust_version"`
//}
// type DependencyDependencyInformation struct {
//	Name           string   `json:"name"`
//	Requirement    string   `json:"req"`
//	Features       []string `json:"features"`
//	Optional       bool     `json:"optional"`
//	DefaultTargets bool     `json:"default_targets"`
//	Target         string   `json:"target"`
//	Kind           string   `json:"kind"`
//	Registry       string   `json:"registry"`
//	Package        string   `json:"package"`
//}
//
// func (r *LockEntry) getIndexPath() string {
// 	return fmt.Sprintf("%s/%s", strings.ToLower(r.getPrefix()), strings.ToLower(r.Name))
// }
//
// func (r *LockEntry) getIndexContent() ([]DependencyInformation, []error) {
// 	var deps []DependencyInformation
// 	var sourceID, err = r.sourceID()
// 	if err != nil {
// 		return deps, []error{err}
// 	}
// 	var content []byte
// 	var errors []error
// 	content, err = sourceID.GetPath(r.getIndexPath())
// 	if err != nil {
// 		return deps, []error{err}
// 	}
// 	for _, v := range bytes.Split(content, []byte("\n")) {
// 		var depInfo = DependencyInformation{
// 			StructVersion: 1,
// 		}
// 		err = json.Unmarshal(v, &depInfo)
// 		if err == nil {
// 			deps = append(deps, depInfo)
// 		} else {
// 			errors = append(errors, err)
// 		}
// 	}
// 	return deps, errors
// }
