package perl

import (
	"context"
	"path"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// mergeDistributions collapses the two kinds of installed evidence into one package per installed
// distribution. A distribution installed by cpanm has both an install.json and a .packlist.
//
// Pairing is scoped to one install tree, so two installs of the same distribution and version into
// separate trees stay two packages. A scan target can hold more than one project tree, and preserving
// that there are two trees is the point: collapsing them asserts one installed thing where there are
// two and loses which tree each belongs to. Multiple projects in one scan target are treated the same
// way elsewhere.
//
// (name, version) alone is not enough to pair them either. A packlist lives at auto/<Module>/.packlist, so its
// name is derived from a MODULE path, while install.json yields the distribution: libwww-perl's packlist
// is auto/LWP/.packlist and produces "LWP" against the distribution "libwww-perl". Those never collide,
// so pairing also consults the `provides` module map, which lists LWP under libwww-perl. Without that
// step every distribution whose main module is named differently from the distribution produces two
// packages, one with the right name and no version and one with the wrong name and the right version,
// and neither one matches an advisory.
func mergeDistributions(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if len(pkgs) < 2 {
		return pkgs, rels, err
	}

	var merged []pkg.Package
	indexByKey := make(map[string]int)

	// install.json evidence is placed first so that the module index is complete before any packlist
	// package needs to resolve against it, independent of the order the parsers ran in
	ordered := make([]pkg.Package, 0, len(pkgs))
	for _, p := range pkgs {
		if fromInstallJSON(p) {
			ordered = append(ordered, p)
		}
	}
	for _, p := range pkgs {
		if !fromInstallJSON(p) {
			ordered = append(ordered, p)
		}
	}

	indexByModule := make(map[string]int)

	for _, p := range ordered {
		tree := installTree(p)
		key := tree + "|" + p.Name + "@" + p.Version
		if idx, exists := indexByKey[key]; exists {
			merged[idx] = mergeInto(merged[idx], p)
			continue
		}

		// a packlist package names a module, so fold it into whichever distribution in the same tree
		// provides it. The version must still agree, or be unreadable: a packlist and an install.json
		// in one tree that disagree describe one install that overwrote another's files, and merging
		// them would report a single version and hide the other.
		if !fromInstallJSON(p) {
			if idx, exists := indexByModule[tree+"|"+moduleFromDashedName(p.Name)]; exists &&
				(p.Version == "" || p.Version == merged[idx].Version) {
				merged[idx] = mergeInto(merged[idx], p)
				continue
			}
		}

		indexByKey[key] = len(merged)
		for _, m := range providedModules(p) {
			// first distribution to claim a module wins; duplicate claims are not expected and
			// silently reassigning would make the result order dependent
			if _, taken := indexByModule[tree+"|"+m]; !taken {
				indexByModule[tree+"|"+m] = len(merged)
			}
		}
		merged = append(merged, p)
	}

	// locations and metadata drive the package ID, and both may have changed
	for i := range merged {
		merged[i].SetID()
	}

	return merged, rels, err
}

// installTree returns the library tree the package's own evidence was found in: the directory holding
// the .meta or auto directory the file sits under. Both kinds of evidence for one install land there,
// in sibling directories rather than the same one, so
// /opt/app/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json and
// /opt/app/lib/perl5/x86_64-linux-gnu/auto/Text/CSV/.packlist both yield
// /opt/app/lib/perl5/x86_64-linux-gnu and still pair.
//
// The owned-file list cannot stand in for this: ExtUtils::Packlist merges an existing packlist for the
// same module when it writes a new one, so a local-lib install's packlist legitimately claims files
// living outside its own prefix.
func installTree(p pkg.Package) string {
	for _, location := range p.Locations.ToSlice() {
		if tree := libRoot(location.Path()); tree != "" {
			return tree
		}
	}
	return ""
}

// libRoot cuts a path at the last auto/ or .meta/ segment, which is where a lib tree ends and the
// installer's own bookkeeping begins. A path with neither, such as a perllocal.pod or a scraped .pm,
// yields "": those are supporting evidence and never the only location a package has.
func libRoot(p string) string {
	parts := strings.Split(p, "/")
	for i := len(parts) - 1; i > 0; i-- {
		if parts[i] == "auto" || parts[i] == ".meta" {
			return strings.Join(parts[:i], "/")
		}
	}
	return ""
}

// moduleFromDashedName converts a packlist-derived name back into the module it came from, since
// auto/IO/Socket/SSL/.packlist flattens IO::Socket::SSL into IO-Socket-SSL.
func moduleFromDashedName(name string) string {
	return strings.ReplaceAll(name, "-", "::")
}

// mergeInto keeps the install.json-derived package, which is the higher fidelity of the two, and folds
// the other's evidence into it.
func mergeInto(a, b pkg.Package) pkg.Package {
	winner, loser := a, b
	if !fromInstallJSON(a) && fromInstallJSON(b) {
		winner, loser = b, a
	}

	locations := file.NewLocationSet(winner.Locations.ToSlice()...)
	locations.Add(loser.Locations.ToSlice()...)
	winner.Locations = locations

	licenses := pkg.NewLicenseSet(winner.Licenses.ToSlice()...)
	licenses.Add(loser.Licenses.ToSlice()...)
	winner.Licenses = licenses

	// the file list only ever comes from a packlist, so the install.json winner has to take the loser's or
	// the merged package would own nothing. OwnedFiles dedupes, which covers a distribution that merged
	// more than one packlist.
	from, fromOK := loser.Metadata.(pkg.CpanDistribution)
	into, intoOK := winner.Metadata.(pkg.CpanDistribution)
	if fromOK && intoOK && len(from.Files) > 0 {
		into.Files = append(into.Files, from.Files...)
		winner.Metadata = into
	}

	return winner
}

// fromInstallJSON reports whether a package was built from an install.json rather than from a
// .packlist. MainModule is only ever set by the packlist parser, so its absence is the direct signal.
func fromInstallJSON(p pkg.Package) bool {
	md, ok := p.Metadata.(pkg.CpanDistribution)
	return ok && md.MainModule == ""
}

// resolveDependencies turns MYMETA.json prereqs into relationships. Prereqs name modules while packages
// are keyed by distribution, so each prereq is looked up in the provides map of the cataloged set. A
// prereq that resolves to nothing (a core module such as Carp, strict, or perl, or a distribution that
// simply is not installed) is dropped rather than turned into a placeholder package.
func resolveDependencies(_ context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if resolver == nil || len(pkgs) == 0 {
		return pkgs, rels, err
	}

	requires := make(map[artifact.ID][]string)
	for i := range pkgs {
		if pkgs[i].ID() == "" {
			pkgs[i].SetID()
		}
		requires[pkgs[i].ID()] = prereqModules(resolver, pkgs[i])
	}

	specifier := func(p pkg.Package) dependency.Specification {
		return dependency.Specification{
			ProvidesRequires: dependency.ProvidesRequires{
				Provides: providedModules(p),
				Requires: requires[p.ID()],
			},
		}
	}

	return pkgs, append(rels, dependency.Resolve(specifier, pkgs)...), err
}

func providedModules(p pkg.Package) []string {
	md, ok := p.Metadata.(pkg.CpanDistribution)
	if !ok {
		return nil
	}

	modules := make([]string, 0, len(md.Modules))
	for _, m := range md.Modules {
		modules = append(modules, m.Name)
	}

	return modules
}

// prereqModules re-reads the MYMETA.json already recorded as evidence on the package. It is read a
// second time (the parser reads it for licenses) rather than carried on the package, since prereqs
// belong in relationships and not in the metadata struct.
func prereqModules(resolver file.Resolver, p pkg.Package) []string {
	for _, location := range p.Locations.ToSlice() {
		if path.Base(location.Path()) != "MYMETA.json" {
			continue
		}
		m, err := decodeMeta(resolver, location)
		if err != nil {
			continue
		}
		return m.prereqModules()
	}
	return nil
}
