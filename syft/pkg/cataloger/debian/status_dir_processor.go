package debian

import (
	"path"
	"sort"
	"strings"

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
	// container is the archive the database was found in, if any, so that databases at the same path within
	// different archives are kept apart
	container    string
	dbDir        string
	name         string
	version      string
	architecture string
}

// mergeStatusDirDuplicates folds packages described by a status.d/<name> file into the package described by the
// status file of the same dpkg database, when both describe the same name, version and architecture. Some images
// record every installed package in both places, which would otherwise report each package twice.
//
// The status file stays the primary evidence of the merged package, and the status.d file becomes supporting evidence.
//
// When several layers are cataloged, the status file can be seen once per layer. Every one of those packages receives
// the status.d package, so they keep a common ID and still collapse into one package downstream.
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

	// every copy of a status entry must agree on the evidence of the status.d entry, since copies from different
	// layers share an ID and only the first annotation seen survives when they collapse downstream
	statusVisible := make(map[dpkgEntryKey]bool)
	for key, targets := range fromStatus {
		for _, target := range targets {
			if l, ok := primaryEvidence(pkgs[target]); ok && isVisible(l) {
				statusVisible[key] = true
			}
		}
	}

	merged := make(map[int]pkg.Package)
	for i, key := range fromStatusDir {
		if len(fromStatus[key]) == 0 {
			// only described in status.d, so there is nothing to merge it into
			delete(fromStatusDir, i)
			continue
		}
		for _, target := range fromStatus[key] {
			into, alreadyMerged := merged[target]
			if !alreadyMerged {
				into = pkgs[target]
			}
			merged[target] = mergeStatusDirPackage(into, pkgs[i], statusVisible[key])
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
		if m, isMerged := merged[i]; isMerged {
			m.SetID()
			p = m
		}
		kept = append(kept, p)
	}

	return kept, rels, err
}

// mergeStatusDirPackage returns the package read from the status file with the evidence, licenses and file listing
// of the same package read from status.d folded into it. The remaining metadata of the status entry is kept as is.
// statusVisible reports whether any copy of the status entry is visible in the final filesystem.
func mergeStatusDirPackage(fromStatus, fromStatusDir pkg.Package, statusVisible bool) pkg.Package {
	// when no copy of the status entry is visible in the final filesystem but the status.d file is, the status.d file
	// is what shows that the package is still installed, so it has to stay primary evidence
	statusDirLocation, ok := primaryEvidence(fromStatusDir)
	keepPrimary := ok && isVisible(statusDirLocation) && !statusVisible

	locations := file.NewLocationSet(fromStatus.Locations.ToSlice()...)
	for _, l := range fromStatusDir.Locations.ToSlice() {
		// annotations are a map shared with the package being folded in, so they are copied before use
		annotations := make(map[string]string, len(l.Annotations))
		for k, v := range l.Annotations {
			annotations[k] = v
		}
		if !keepPrimary && annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			annotations[pkg.EvidenceAnnotationKey] = pkg.SupportingEvidenceAnnotation
		}
		l.Annotations = annotations
		locations.Add(l)
	}
	fromStatus.Locations = locations

	licenses := pkg.NewLicenseSet(fromStatus.Licenses.ToSlice()...)
	licenses.Add(fromStatusDir.Licenses.ToSlice()...)
	fromStatus.Licenses = licenses

	// the file listing is read from beside whichever file described the package (info/ for status, status.d/ itself
	// otherwise), so the status entry can be missing files that only the status.d entry knows about
	from, fromOK := fromStatusDir.Metadata.(pkg.DpkgDBEntry)
	into, intoOK := fromStatus.Metadata.(pkg.DpkgDBEntry)
	if fromOK && intoOK && len(from.Files) > 0 {
		into.Files = mergeDpkgFileRecords(into.Files, from.Files)
		fromStatus.Metadata = into
	}

	return fromStatus
}

// mergeDpkgFileRecords returns the existing records plus any additional records for paths not already present,
// sorted by path.
func mergeDpkgFileRecords(existing, additional []pkg.DpkgFileRecord) []pkg.DpkgFileRecord {
	paths := make(map[string]struct{}, len(existing))
	files := make([]pkg.DpkgFileRecord, 0, len(existing)+len(additional))
	for _, f := range existing {
		paths[f.Path] = struct{}{}
		files = append(files, f)
	}
	for _, f := range additional {
		if _, exists := paths[f.Path]; exists {
			continue
		}
		paths[f.Path] = struct{}{}
		files = append(files, f)
	}
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	return files
}

// dpkgKey returns the identity of a dpkg DB package and whether it was read from a status.d directory. ok is false
// for packages that did not come from a dpkg status file or status.d directory.
func dpkgKey(p pkg.Package) (key dpkgEntryKey, inStatusDir bool, ok bool) {
	entry, isDpkgEntry := p.Metadata.(pkg.DpkgDBEntry)
	if !isDpkgEntry {
		return dpkgEntryKey{}, false, false
	}
	dbLocation, hasPrimary := primaryEvidence(p)
	if !hasPrimary {
		return dpkgEntryKey{}, false, false
	}

	// for a database within an archive the real path is that of the archive, so the path within it is used
	localPath := dbLocation.LocalPath()
	dir := path.Dir(localPath)
	inStatusDir = path.Base(dir) == statusDirName
	switch {
	case inStatusDir:
		dir = path.Dir(dir)
	case path.Base(localPath) != statusFileName:
		return dpkgEntryKey{}, false, false
	}

	return dpkgEntryKey{
		container:    strings.TrimSuffix(dbLocation.FullNestedPath(), localPath),
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

// isVisible reports whether a location is marked as present in the final filesystem. Locations carry no such mark
// unless the scan distinguishes hidden files from visible ones.
func isVisible(l file.Location) bool {
	return l.Annotations[file.VisibleAnnotationKey] == file.VisibleAnnotation
}
