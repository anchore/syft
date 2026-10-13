package spdxhelpers

import (
	"fmt"
	"testing"
	"time"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file cover findRootPackages, which locates the packages an SPDX document declares it DESCRIBES
// (or which declare themselves DESCRIBED_BY the document). Until it was rewritten, this function compared every
// package against every relationship, so its cost grew with packages x relationships. On real documents that made
// SPDX decoding quadratic in document size: a 119MB SPDX JSON document (70k packages, 153k relationships) spent
// 72s here, a 238MB document 266s, and a 1.3GB document did not finish within 90 minutes. Encoding the same
// documents, and decoding equivalently sized syft-json or CycloneDX documents, is linear and takes seconds.
//
// Test_findRootPackages pins the exact semantics of the original implementation, including the corner cases a
// rewrite could easily change: result order follows package order, an element described twice appears twice, and
// only edges that touch the DOCUMENT element count. Test_findRootPackages_scalesLinearly is the regression guard
// for the performance fix itself.

func Test_findRootPackages(t *testing.T) {
	pkgA := &spdx.Package{PackageSPDXIdentifier: "Package-a"}
	pkgB := &spdx.Package{PackageSPDXIdentifier: "Package-b"}
	pkgC := &spdx.Package{PackageSPDXIdentifier: "Package-c"}

	describes := func(id common.ElementID) *spdx.Relationship {
		return &spdx.Relationship{
			RefA:         common.DocElementID{ElementRefID: "DOCUMENT"},
			RefB:         common.DocElementID{ElementRefID: id},
			Relationship: spdx.RelationshipDescribes,
		}
	}
	describedBy := func(id common.ElementID) *spdx.Relationship {
		return &spdx.Relationship{
			RefA:         common.DocElementID{ElementRefID: id},
			RefB:         common.DocElementID{ElementRefID: "DOCUMENT"},
			Relationship: spdx.RelationshipDescribedBy,
		}
	}

	tests := []struct {
		name          string
		packages      []*spdx.Package
		relationships []*spdx.Relationship
		want          []*spdx.Package
	}{
		{
			name:          "no relationships",
			packages:      []*spdx.Package{pkgA, pkgB},
			relationships: nil,
			want:          nil,
		},
		{
			name:     "document describes one package",
			packages: []*spdx.Package{pkgA, pkgB, pkgC},
			relationships: []*spdx.Relationship{
				{RefA: common.DocElementID{ElementRefID: "Package-a"}, RefB: common.DocElementID{ElementRefID: "Package-b"}, Relationship: spdx.RelationshipContains},
				describes("Package-b"),
			},
			want: []*spdx.Package{pkgB},
		},
		{
			name:     "package described by the document",
			packages: []*spdx.Package{pkgA, pkgB, pkgC},
			relationships: []*spdx.Relationship{
				describedBy("Package-c"),
			},
			want: []*spdx.Package{pkgC},
		},
		{
			name:     "multiple roots are returned in package order",
			packages: []*spdx.Package{pkgA, pkgB, pkgC},
			relationships: []*spdx.Relationship{
				describes("Package-c"),
				describedBy("Package-a"),
			},
			want: []*spdx.Package{pkgA, pkgC},
		},
		{
			name:     "duplicate edges yield duplicate roots (preserved behavior)",
			packages: []*spdx.Package{pkgA, pkgB},
			relationships: []*spdx.Relationship{
				describes("Package-a"),
				describedBy("Package-a"),
			},
			want: []*spdx.Package{pkgA, pkgA},
		},
		{
			name:     "describes edges not from the document are ignored",
			packages: []*spdx.Package{pkgA, pkgB},
			relationships: []*spdx.Relationship{
				{RefA: common.DocElementID{ElementRefID: "Package-a"}, RefB: common.DocElementID{ElementRefID: "Package-b"}, Relationship: spdx.RelationshipDescribes},
				{RefA: common.DocElementID{ElementRefID: "Package-b"}, RefB: common.DocElementID{ElementRefID: "Package-a"}, Relationship: spdx.RelationshipDescribedBy},
			},
			want: nil,
		},
		{
			name:     "described element that is not a package is ignored",
			packages: []*spdx.Package{pkgA},
			relationships: []*spdx.Relationship{
				describes("File-1"),
			},
			want: nil,
		},
		{
			name:     "nil packages and relationships are skipped",
			packages: []*spdx.Package{nil, pkgA},
			relationships: []*spdx.Relationship{
				nil,
				describes("Package-a"),
			},
			want: []*spdx.Package{pkgA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findRootPackages(&spdx.Document{
				Packages:      tt.packages,
				Relationships: tt.relationships,
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

// Test_findRootPackages_scalesLinearly guards against reintroducing a packages x relationships scan. At 50k
// packages and 100k relationships (5e9 comparisons) the previous implementation needs on the order of a minute on
// a fast laptop and several minutes on a CI runner, whereas the indexed implementation completes in about a
// millisecond. The 10s bound is therefore loose enough never to flake on slow hardware yet far below what any
// quadratic implementation could achieve.
func Test_findRootPackages_scalesLinearly(t *testing.T) {
	doc := largeSPDXDocument(50_000, 100_000)

	start := time.Now()
	got := findRootPackages(doc)
	elapsed := time.Since(start)

	require.Len(t, got, 1)
	assert.Equal(t, common.ElementID("Package-0"), got[0].PackageSPDXIdentifier)
	assert.Less(t, elapsed, 10*time.Second, "findRootPackages took %s on %d packages and %d relationships", elapsed, len(doc.Packages), len(doc.Relationships))
}

// Benchmark_findRootPackages measures the same 50k x 100k document as the scaling test so the two can be compared
// directly: run with `go test ./syft/format/common/spdxhelpers/ -run xxx -bench findRootPackages`.
func Benchmark_findRootPackages(b *testing.B) {
	doc := largeSPDXDocument(50_000, 100_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = findRootPackages(doc)
	}
}

// largeSPDXDocument builds a document with the given number of packages and relationships where the document
// describes exactly the first package and every other relationship links packages to one another.
func largeSPDXDocument(packages int, relationships int) *spdx.Document {
	doc := &spdx.Document{}
	for i := 0; i < packages; i++ {
		doc.Packages = append(doc.Packages, &spdx.Package{
			PackageSPDXIdentifier: common.ElementID(fmt.Sprintf("Package-%d", i)),
		})
	}
	doc.Relationships = append(doc.Relationships, &spdx.Relationship{
		RefA:         common.DocElementID{ElementRefID: "DOCUMENT"},
		RefB:         common.DocElementID{ElementRefID: "Package-0"},
		Relationship: spdx.RelationshipDescribes,
	})
	for i := 1; i < relationships; i++ {
		doc.Relationships = append(doc.Relationships, &spdx.Relationship{
			RefA:         common.DocElementID{ElementRefID: common.ElementID(fmt.Sprintf("Package-%d", i%packages))},
			RefB:         common.DocElementID{ElementRefID: common.ElementID(fmt.Sprintf("Package-%d", (i+1)%packages))},
			Relationship: spdx.RelationshipDependsOn,
		})
	}
	return doc
}
