package dependency

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func TestRelationshipResolver_Resolve(t *testing.T) {
	a := pkg.Package{
		Name: "a",
	}
	a.SetID()

	b := pkg.Package{
		Name: "b",
	}
	b.SetID()

	c := pkg.Package{
		Name: "c",
	}
	c.SetID()

	subjects := []pkg.Package{a, b, c}

	tests := []struct {
		name string
		s    Specifier
		want map[string][]string
	}{
		{
			name: "find relationships between packages",
			s: newSpecifierBuilder().
				WithProvides(a /* provides */, "a-resource").
				WithRequires(b /* requires */, "a-resource").
				Specifier(),
			want: map[string][]string{
				"b": /* depends on */ {"a"},
			},
		},
		{
			name: "deduplicates provider keys",
			s: newSpecifierBuilder().
				WithProvides(a /* provides */, "a-resource", "a-resource", "a-resource").
				WithRequires(b /* requires */, "a-resource", "a-resource", "a-resource").
				Specifier(),
			want: map[string][]string{
				"b": /* depends on */ {"a"},
				// note: we're NOT seeing:
				// "b": /* depends on */ {"a", "a", "a"},
			},
		},
		{
			name: "deduplicates crafted relationships",
			s: newSpecifierBuilder().
				WithProvides(a /* provides */, "a1-resource", "a2-resource", "a3-resource").
				WithRequires(b /* requires */, "a1-resource", "a2-resource").
				Specifier(),
			want: map[string][]string{
				"b": /* depends on */ {"a"},
				// note: we're NOT seeing:
				// "b": /* depends on */ {"a", "a"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relationships := NewRelationshipResolver(tt.s).Resolve(subjects)
			if d := cmp.Diff(tt.want, abstractRelationships(t, relationships)); d != "" {
				t.Errorf("unexpected relationships (-want +got):\n%s", d)
			}
		})
	}
}

type specifierBuilder struct {
	provides map[string][]string
	requires map[string][]string
}

func newSpecifierBuilder() *specifierBuilder {
	return &specifierBuilder{
		provides: make(map[string][]string),
		requires: make(map[string][]string),
	}
}

func (m *specifierBuilder) WithProvides(p pkg.Package, provides ...string) *specifierBuilder {
	m.provides[p.Name] = append(m.provides[p.Name], provides...)
	return m
}

func (m *specifierBuilder) WithRequires(p pkg.Package, requires ...string) *specifierBuilder {
	m.requires[p.Name] = append(m.requires[p.Name], requires...)
	return m
}

func (m specifierBuilder) Specifier() Specifier {
	return func(p pkg.Package) Specification {
		return Specification{
			Provides: m.provides[p.Name],
			Requires: m.requires[p.Name],
		}
	}
}

func abstractRelationships(t testing.TB, relationships []artifact.Relationship) map[string][]string {
	t.Helper()

	abstracted := make(map[string][]string)
	for _, relationship := range relationships {
		fromPkg, ok := relationship.From.(pkg.Package)
		if !ok {
			continue
		}
		toPkg, ok := relationship.To.(pkg.Package)
		if !ok {
			continue
		}

		// we build this backwards since we use DependencyOfRelationship instead of DependsOn
		abstracted[toPkg.Name] = append(abstracted[toPkg.Name], fromPkg.Name)
	}

	return abstracted
}

func Test_Processor(t *testing.T) {
	a := pkg.Package{
		Name: "a",
	}
	a.SetID()

	b := pkg.Package{
		Name: "b",
	}
	b.SetID()

	c := pkg.Package{
		Name: "c",
	}
	c.SetID()

	tests := []struct {
		name         string
		sp           Specifier
		pkgs         []pkg.Package
		rels         []artifact.Relationship
		err          error
		wantPkgCount int
		wantRelCount int
		wantErr      assert.ErrorAssertionFunc
	}{
		{
			name: "happy path preserves decorated values",
			sp: newSpecifierBuilder().
				WithProvides(b, "b-resource").
				WithRequires(c, "b-resource").
				Specifier(),
			pkgs: []pkg.Package{a, b, c},
			rels: []artifact.Relationship{
				{
					From: a,
					To:   b,
					Type: artifact.DependencyOfRelationship,
				},
			},

			wantPkgCount: 3,
			wantRelCount: 2, // original + new
		},
		{
			name: "error from cataloger is propagated",
			sp: newSpecifierBuilder().
				WithProvides(b, "b-resource").
				WithRequires(c, "b-resource").
				Specifier(),
			err:  errors.New("surprise!"),
			pkgs: []pkg.Package{a, b, c},
			rels: []artifact.Relationship{
				{
					From: a,
					To:   b,
					Type: artifact.DependencyOfRelationship,
				},
			},
			wantPkgCount: 3,
			wantRelCount: 2, // original + new
			wantErr:      assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}

			gotPkgs, gotRels, err := Processor(tt.sp)(tt.pkgs, tt.rels, tt.err)

			tt.wantErr(t, err)
			assert.Len(t, gotPkgs, tt.wantPkgCount)
			assert.Len(t, gotRels, tt.wantRelCount)
		})
	}
}
