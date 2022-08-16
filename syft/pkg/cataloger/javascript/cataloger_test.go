package javascript

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func Test_JavascriptCataloger(t *testing.T) {
	expected := map[string]pkg.Package{
		"@actions/core": {
			Name:     "@actions/core",
			Version:  "1.6.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
		"wordwrap": {
			Name:     "wordwrap",
			Version:  "0.0.3",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"get-stdin": {
			Name:     "get-stdin",
			Version:  "5.0.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"minimist": {
			Name:     "minimist",
			Version:  "0.0.10",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"optimist": {
			Name:     "optimist",
			Version:  "0.6.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"string-width": {
			Name:     "string-width",
			Version:  "2.1.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"strip-ansi": {
			Name:     "strip-ansi",
			Version:  "4.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"strip-eof": {
			Name:     "wordwrap",
			Version:  "1.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"ansi-regex": {
			Name:     "ansi-regex",
			Version:  "3.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"is-fullwidth-code-point": {
			Name:     "is-fullwidth-code-point",
			Version:  "2.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"cowsay": {
			Name:     "cowsay",
			Version:  "1.4.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
	}

	s, err := source.NewFromDirectory("test-fixtures/pkg-lock")
	require.NoError(t, err)

	resolver, err := s.FileResolver(source.AllLayersScope)
	require.NoError(t, err)

	actual, _, err := NewJavascriptLockCataloger().Catalog(resolver)
	if err != nil {
		t.Fatalf("failed to parse package-lock.json: %+v", err)
	}

	var pkgs []*pkg.Package
	for _, p := range actual {
		p2 := p
		pkgs = append(pkgs, &p2)
	}

	assertPkgsEqual(t, pkgs, expected)
}
