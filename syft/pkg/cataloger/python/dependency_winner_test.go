package python

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func pythonPkgAt(name, version, realPath string) pkg.Package {
	return pkg.Package{
		Name:    name,
		Version: version,
		Locations: file.NewLocationSet(
			file.NewLocation(realPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	}
}

// bucketBySiteAndName mirrors the indexing wheelEggRelationships performs, so this test
// exercises the real bucketing decision rather than a stub.
func bucketBySiteAndName(pkgs []pkg.Package) map[string]pkg.Package {
	bySite := make(map[string]map[string]pkg.Package)
	for _, p := range pkgs {
		site := deriveSitePackageDir(p)
		if bySite[site] == nil {
			bySite[site] = make(map[string]pkg.Package)
		}
		if existing, ok := bySite[site][p.Name]; ok && !preferPackage(p, existing) {
			continue
		}
		bySite[site][p.Name] = p
	}
	return bySite[deriveSitePackageDir(pkgs[0])]
}

// A distribution installed both top-level and vendored inside another distribution's
// wheel resolves to the same site-packages dir, so the two copies must not collapse onto
// whichever one happened to be catalogued last.
func Test_sitePackageBucketing_sameNameCopiesShareOneSiteDir(t *testing.T) {
	site := "/venv/lib/python3.11/site-packages"
	topLevel := pythonPkgAt("packaging", "26.3", site+"/packaging/__init__.py")
	vendored := pythonPkgAt("packaging", "24.2", site+"/setuptools/_vendor/packaging/__init__.py")

	if top, vend := deriveSitePackageDir(topLevel), deriveSitePackageDir(vendored); top != vend {
		t.Fatalf("expected both copies in one site-packages dir, got %q and %q", top, vend)
	}

	forward := bucketBySiteAndName([]pkg.Package{topLevel, vendored})
	reverse := bucketBySiteAndName([]pkg.Package{vendored, topLevel})

	if forward["packaging"].Version != reverse["packaging"].Version {
		t.Fatalf("bucketing depends on cataloguing order: forward kept %s, reverse kept %s",
			forward["packaging"].Version, reverse["packaging"].Version)
	}
	if got := forward["packaging"].Version; got != "26.3" {
		t.Fatalf("expected the top-level copy (26.3) to win over the vendored one (24.2), got %s", got)
	}
}

// preferPackage must prefer the shallowest install and never let a deeper copy displace
// a shallower one that was catalogued first.
func Test_preferPackage_prefersShallowestInstall(t *testing.T) {
	shallow := pythonPkgAt("x", "1.0", "/s/x/__init__.py")
	deep := pythonPkgAt("x", "2.0", "/s/a/b/x/__init__.py")

	if !preferPackage(shallow, deep) {
		t.Fatal("shallower install must win")
	}
	if preferPackage(deep, shallow) {
		t.Fatal("deeper install must not displace a shallower one")
	}

	// equal depth must still resolve deterministically, by path
	a := pythonPkgAt("x", "1.0", "/s/a/x/__init__.py")
	b := pythonPkgAt("x", "2.0", "/s/b/x/__init__.py")
	if !preferPackage(a, b) {
		t.Fatal("equal-depth installs must tie-break by path: /s/a/... sorts before /s/b/...")
	}
	if preferPackage(b, a) {
		t.Fatal("equal-depth tie-break must be antisymmetric")
	}
}
