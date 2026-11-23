package debian

import (
	"maps"
	"path"
	"sort"
	"strings"

	"github.com/anchore/syft/internal/relationship"
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
	// the package that each package was merged into, and the status.d packages no longer reported on their own
	mergedInto := make(map[int]pkg.Package)
	dropped := make(map[int]bool)
	for _, e := range groupDpkgEntries(pkgs) {
		if len(e.status) == 0 || len(e.statusDir) == 0 {
			continue
		}

		// copies of the status entry from different layers share an ID, and only the first annotation seen survives
		// when they collapse downstream, so they must all agree on the evidence of the status.d entry
		statusVisible := false
		for _, i := range e.status {
			if l, ok := primaryEvidence(pkgs[i]); ok && isVisible(l) {
				statusVisible = true
			}
		}

		for _, target := range e.status {
			m := pkgs[target]
			for _, i := range e.statusDir {
				m = mergeStatusDirPackage(m, pkgs[i], statusVisible)
			}
			m.SetID()
			mergedInto[target] = m
		}
		for _, i := range e.statusDir {
			dropped[i] = true
			// every status copy carries the same merged ID, so any of them will do
			mergedInto[i] = mergedInto[e.status[0]]
		}
	}
	if len(dropped) == 0 {
		return pkgs, rels, err
	}

	kept := make([]pkg.Package, 0, len(pkgs)-len(dropped))
	for i, p := range pkgs {
		if dropped[i] {
			continue
		}
		if m, isMerged := mergedInto[i]; isMerged {
			p = m
		}
		kept = append(kept, p)
	}

	return kept, followMergedPackages(rels, pkgs, mergedInto), err
}

// dpkgEntry holds the indexes of the packages describing one dpkg entry, in package order so that merging is
// deterministic.
type dpkgEntry struct {
	status, statusDir []int
}

func groupDpkgEntries(pkgs []pkg.Package) map[dpkgEntryKey]*dpkgEntry {
	entries := make(map[dpkgEntryKey]*dpkgEntry)
	for i, p := range pkgs {
		key, inStatusDir, ok := dpkgKey(p)
		if !ok {
			continue
		}
		e := entries[key]
		if e == nil {
			e = &dpkgEntry{}
			entries[key] = e
		}
		if inStatusDir {
			e.statusDir = append(e.statusDir, i)
		} else {
			e.status = append(e.status, i)
		}
	}
	return entries
}

// followMergedPackages points relationships at the package that each package was merged into, since merging drops
// status.d packages and changes the ID of the status packages they were folded into.
func followMergedPackages(rels []artifact.Relationship, pkgs []pkg.Package, mergedInto map[int]pkg.Package) []artifact.Relationship {
	if len(rels) == 0 {
		return rels
	}
	idx := relationship.NewIndex(rels...)
	for i, m := range mergedInto {
		idx.Replace(pkgs[i].ID(), m)
	}
	return idx.All()
}

// mergeStatusDirPackage returns the package read from the status file with the evidence, licenses and file listing
// of the same package read from status.d folded into it. The remaining metadata of the status entry is kept as is.
// statusVisible reports whether any copy of the status entry is visible in the final filesystem.
func mergeStatusDirPackage(fromStatus, fromStatusDir pkg.Package, statusVisible bool) pkg.Package {
	// when no copy of the status entry is visible in the final filesystem but the status.d file is, the status.d file
	// is what shows that the package is still installed, so it has to stay primary evidence
	statusDirLocation, ok := primaryEvidence(fromStatusDir)
	keepPrimary := ok && isVisible(statusDirLocation) && !statusVisible

	locations := file.NewLocationSet()
	for _, l := range fromStatus.Locations.ToSlice() {
		locations.Add(withCopiedAnnotations(l))
	}
	for _, l := range fromStatusDir.Locations.ToSlice() {
		l = withCopiedAnnotations(l)
		if !keepPrimary && l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			l.Annotations[pkg.EvidenceAnnotationKey] = pkg.SupportingEvidenceAnnotation
		}
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

// withCopiedAnnotations returns the location with its own copy of the annotations, which are otherwise a map shared
// with every copy of the location.
func withCopiedAnnotations(l file.Location) file.Location {
	annotations := make(map[string]string, len(l.Annotations))
	maps.Copy(annotations, l.Annotations)
	l.Annotations = annotations
	return l
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
