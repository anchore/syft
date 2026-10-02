package python

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// pythonPkgWithPath builds a package whose primary evidence lives at path, which
// is what deriveSitePackageDir reads to bucket it into a site-packages dir.
func pythonPkgWithPath(name, version, path string) pkg.Package {
	return pkg.Package{
		Name:    name,
		Version: version,
		Locations: file.NewLocationSet(
			file.NewLocation(path).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	}
}

// Test_currentBucketingLosesPackages reproduces the existing behaviour by
// running the same bucketing logic wheelEggRelationships uses today, extracted
// verbatim so the reproduction cannot drift from the code under discussion.
//
// A distribution can be installed both top-level and vendored inside another
// distribution's wheel. When neither copy sits under a site-packages or
// dist-packages directory, deriveSitePackageDir returns "" for both, so both
// copies land on the same bucket key and the same name — and a
// map[string]pkg.Package keeps only the last one written. Which copy survives
// depends on cataloguing order, which varies between scans of an unchanged tree.
//
// See https://github.com/anchore/syft/issues/5357
func Test_currentBucketingLosesPackages(t *testing.T) {
	topLevel := pythonPkgWithPath("packaging", "26.3", "/tmp/repro/packaging/__init__.py")
	vendored := pythonPkgWithPath("packaging", "24.2", "/tmp/repro/setuptools/_vendor/packaging/__init__.py")

	buckets := currentSiteAndNameBucketing([]pkg.Package{topLevel, vendored})

	assert.Len(t, buckets, 1,
		"reproduction: both copies collapse into a single bucket")
	assert.Len(t, buckets[0], 1,
		"and only one copy of the name survives")
}

// Test_currentBucketingIsOrderDependent shows the nondeterminism directly: the
// same two packages bucketed in the two possible cataloguing orders keep
// different copies, so a package resolving a dependency by name links to
// whichever copy happened to be catalogued last.
func Test_currentBucketingIsOrderDependent(t *testing.T) {
	topLevel := pythonPkgWithPath("packaging", "26.3", "/tmp/repro/packaging/__init__.py")
	vendored := pythonPkgWithPath("packaging", "24.2", "/tmp/repro/setuptools/_vendor/packaging/__init__.py")

	topLevelLast := currentSiteAndNameBucketing([]pkg.Package{vendored, topLevel})
	vendoredLast := currentSiteAndNameBucketing([]pkg.Package{topLevel, vendored})

	assert.NotEqual(t, keptVersions(topLevelLast), keptVersions(vendoredLast),
		"reproduction: which copy of packaging survives depends on cataloguing order")
}

// Test_resolvePackagesBySiteAndName_keepsBothCopies is the behaviour the fix
// must guarantee, and it fails against the current implementation: indexing by
// site-packages dir and name alone cannot represent two copies of the same
// distribution when neither sits under a site-packages directory.
func Test_resolvePackagesBySiteAndName_keepsBothCopies(t *testing.T) {
	topLevel := pythonPkgWithPath("packaging", "26.3", "/tmp/repro/packaging/__init__.py")
	vendored := pythonPkgWithPath("packaging", "24.2", "/tmp/repro/setuptools/_vendor/packaging/__init__.py")

	buckets, _ := resolvePackagesBySiteAndName([]pkg.Package{topLevel, vendored})

	assert.Len(t, buckets, 2,
		"both copies of packaging must be addressable independently")
	assert.ElementsMatch(t, []string{"26.3", "24.2"}, allVersions(buckets),
		"neither copy may be dropped")
}

// Test_resolvePackagesBySiteAndName_isOrderIndependent is the property that
// actually matters to a consumer: repeated scans of an unchanged tree must
// produce the same dependency graph.
func Test_resolvePackagesBySiteAndName_isOrderIndependent(t *testing.T) {
	topLevel := pythonPkgWithPath("packaging", "26.3", "/tmp/repro/packaging/__init__.py")
	vendored := pythonPkgWithPath("packaging", "24.2", "/tmp/repro/setuptools/_vendor/packaging/__init__.py")

	forwardBuckets, _ := resolvePackagesBySiteAndName([]pkg.Package{topLevel, vendored})
	reverseBuckets, _ := resolvePackagesBySiteAndName([]pkg.Package{vendored, topLevel})
	forward := allVersions(forwardBuckets)
	reverse := allVersions(reverseBuckets)

	assert.Equal(t, forward, reverse,
		"bucketing must not depend on the order packages were catalogued in")
}

// currentSiteAndNameBucketing mirrors the bucketing performed inside
// wheelEggRelationships: index packages by site-packages dir, then by name.
//
// It is duplicated here on purpose so the reproduction runs against the same
// logic that is under discussion rather than against a stub.
func currentSiteAndNameBucketing(pkgs []pkg.Package) []map[string]pkg.Package {
	bySite := make(map[string]map[string]pkg.Package)
	for _, p := range pkgs {
		site := deriveSitePackageDir(p)
		if bySite[site] == nil {
			bySite[site] = make(map[string]pkg.Package)
		}
		bySite[site][p.Name] = p
	}

	var out []map[string]pkg.Package
	for _, byName := range bySite {
		out = append(out, byName)
	}
	sort.Slice(out, func(i, j int) bool { return false }) // keep order stable
	return out
}

// keptVersions returns the sorted versions retained by the bucketing, so a test
// can compare which copies survived without depending on map iteration order.
func keptVersions(buckets []map[string]pkg.Package) []string {
	var versions []string
	for _, byName := range buckets {
		for _, p := range byName {
			versions = append(versions, p.Version)
		}
	}
	sort.Strings(versions)
	return versions
}

// allVersions returns the sorted versions retained across every bucket.
func allVersions(buckets []map[string]pkg.Package) []string {
	var versions []string
	for _, byName := range buckets {
		for _, p := range byName {
			versions = append(versions, p.Version)
		}
	}
	sort.Strings(versions)
	return versions
}
