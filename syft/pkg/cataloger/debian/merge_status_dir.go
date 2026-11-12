package debian

import (
	"path"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const (
	statusFileName = "status"
	statusDirName  = "status.d"
)

// dpkgEntryKey identifies one installed package within one dpkg database directory.
type dpkgEntryKey struct {
	dbDir        string
	name         string
	version      string
	architecture string
}

// mergeStatusDirDuplicates folds packages described by a status.d/<name> file into the package described by the
// status file of the same dpkg database, when both describe the same name, version and architecture. Some images
// record every installed package in both places, which would otherwise report each package twice.
//
// When several layers are cataloged, the status file can be seen once per layer. Every one of those packages receives
// the status.d locations, so they keep a common ID and still collapse into one package downstream.
func mergeStatusDirDuplicates(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	// packages read from a status file, by identity
	fromStatus := make(map[dpkgEntryKey][]int)
	// packages read from a status.d directory, by index
	fromStatusDir := make(map[int]dpkgEntryKey)
	for i, p := range pkgs {
		key, inStatusDir, ok := dpkgKey(p)
		switch {
		case !ok:
			continue
		case inStatusDir:
			fromStatusDir[i] = key
		default:
			fromStatus[key] = append(fromStatus[key], i)
		}
	}

	targets := make(map[int]struct{})
	for i, key := range fromStatusDir {
		if len(fromStatus[key]) == 0 {
			// only described in status.d, so there is nothing to merge it into
			delete(fromStatusDir, i)
			continue
		}
		for _, target := range fromStatus[key] {
			pkgs[target].Locations.Add(pkgs[i].Locations.ToSlice()...)
			pkgs[target].Licenses.Add(pkgs[i].Licenses.ToSlice()...)
			targets[target] = struct{}{}
		}
	}
	if len(fromStatusDir) == 0 {
		return pkgs, rels, err
	}

	kept := make([]pkg.Package, 0, len(pkgs)-len(fromStatusDir))
	for i, p := range pkgs {
		if _, isDuplicate := fromStatusDir[i]; isDuplicate {
			continue
		}
		if _, isTarget := targets[i]; isTarget {
			p.SetID()
		}
		kept = append(kept, p)
	}

	return kept, rels, err
}

// dpkgKey returns the identity of a dpkg DB package and whether it was read from a status.d directory. The last
// return value is false for packages that did not come from a dpkg status file or status.d directory.
func dpkgKey(p pkg.Package) (dpkgEntryKey, bool, bool) {
	entry, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		return dpkgEntryKey{}, false, false
	}
	dbLocation, ok := primaryEvidence(p)
	if !ok {
		return dpkgEntryKey{}, false, false
	}

	dir := path.Dir(dbLocation.RealPath)
	inStatusDir := path.Base(dir) == statusDirName
	switch {
	case inStatusDir:
		dir = path.Dir(dir)
	case path.Base(dbLocation.RealPath) != statusFileName:
		return dpkgEntryKey{}, false, false
	}

	return dpkgEntryKey{
		dbDir:        dir,
		name:         p.Name,
		version:      p.Version,
		architecture: entry.Architecture,
	}, inStatusDir, true
}

func primaryEvidence(p pkg.Package) (file.Location, bool) {
	for _, l := range p.Locations.ToSlice() {
		if l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			return l, true
		}
	}
	return file.Location{}, false
}
