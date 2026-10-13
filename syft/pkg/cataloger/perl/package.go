package perl

import (
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// newCpanPackage builds a package for a CPAN distribution. Note that the name and version are passed
// separately rather than living on the metadata struct: they would be verbatim copies of the package
// fields, so they are not duplicated into metadata.
//
// The metadata is an `any` because the two evidence tiers carry different types, and the author is an
// explicit parameter for the same reason: pkg.CpanUnpackedRelease has no PAUSE path, so there is no
// field on it the purl could be built from.
func newCpanPackage(name, version, author string, md any, licenses []pkg.License, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      packageURL(name, version, author),
		Locations: file.NewLocationSet(locations...),
		Licenses:  pkg.NewLicenseSet(licenses...),
		Language:  pkg.Perl,
		Type:      pkg.CpanPkg,
		Metadata:  md,
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for a CPAN distribution. The distribution name is used verbatim: CPAN
// names are case sensitive. The author is emitted as a qualifier rather than as the namespace, which
// is what the current purl spec prefers, and is omitted entirely when unknown rather than guessed.
func packageURL(name, version, author string) string {
	var qualifiers packageurl.Qualifiers
	if author != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "author", Value: author})
	}

	return packageurl.NewPackageURL(packageurl.TypeCpan, "", name, version, qualifiers, "").ToString()
}

// authorFromPathname extracts the CPAN author (PAUSE) ID from a PAUSE path such as
// O/OA/OALDERS/URI-5.35.tar.gz. A path with fewer than three segments yields no author rather than a
// partial one.
func authorFromPathname(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// modulesFromProvides converts a CPAN metadata `provides` map into a stable, sorted module list.
// The `file` field is dropped: the installed path is mechanical from the module name.
func modulesFromProvides(provides map[string]providesEntry) []pkg.CpanModule {
	if len(provides) == 0 {
		return nil
	}

	modules := make([]pkg.CpanModule, 0, len(provides))
	for name, entry := range provides {
		modules = append(modules, pkg.CpanModule{Name: name, Version: string(entry.Version)})
	}

	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })

	return modules
}
