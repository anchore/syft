package dependency

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

var _ pkg.Cataloger = (*catalogerDecorator)(nil)

type mockCataloger struct {
	pkgs []pkg.Package
	rels []artifact.Relationship
	err  error
}

func (m mockCataloger) Name() string {
	return "mock"
}

func (m mockCataloger) Catalog(_ context.Context, _ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return m.pkgs, m.rels, m.err
}

func Test_catalogerDecorator_Catalog(t *testing.T) {
	a := pkg.Package{
		Name: "a",
	}

	b := pkg.Package{
		Name: "b",
	}

	c := pkg.Package{
		Name: "c",
	}

	subjects := []pkg.Package{a, b, c}

	for _, p := range subjects {
		p.SetID()
	}

	tests := []struct {
		name         string
		prosumer     Prosumer
		cataloger    pkg.Cataloger
		wantPkgCount int
		wantRelCount int
		wantErr      assert.ErrorAssertionFunc
	}{
		{
			name:     "happy path preserves decorated values",
			prosumer: newMockProsumer().WithProvides(b, "b-resource").WithRequires(c, "b-resource"),
			cataloger: mockCataloger{
				pkgs: []pkg.Package{a, b, c},
				rels: []artifact.Relationship{
					{
						From: a,
						To:   b,
						Type: artifact.DependencyOfRelationship,
					},
				},
			},
			wantPkgCount: 3,
			wantRelCount: 2, // original + new
		},
		{
			name:     "error from cataloger is propagated",
			prosumer: newMockProsumer().WithProvides(b, "b-resource").WithRequires(c, "b-resource"),
			cataloger: mockCataloger{
				err:  errors.New("surprise!"),
				pkgs: []pkg.Package{a, b, c},
				rels: []artifact.Relationship{
					{
						From: a,
						To:   b,
						Type: artifact.DependencyOfRelationship,
					},
				},
			},
			wantPkgCount: 0,
			wantRelCount: 0,
			wantErr:      assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}

			gotPkgs, gotRels, err := DecorateCatalogerWithRelationships(tt.cataloger, tt.prosumer).Catalog(context.Background(), nil)

			tt.wantErr(t, err)
			assert.Len(t, gotPkgs, tt.wantPkgCount)
			assert.Len(t, gotRels, tt.wantRelCount)
		})
	}
}
