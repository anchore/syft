package javascript

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseYarnLock(t *testing.T) {
	expected := map[string]pkg.Package{
		"@babel/code-frame": {
			Name:     "@babel/code-frame",
			Version:  "7.10.4",
			Language: pkg.JavaScript,
			Type:     pkg.YarnPkg,
		},
		"@types/minimatch": {
			Name:     "@types/minimatch",
			Version:  "3.0.3",
			Language: pkg.JavaScript,
			Type:     pkg.YarnPkg,
		},
		"@types/qs": {
			Name:     "@types/qs",
			Version:  "6.9.4",
			Language: pkg.JavaScript,
			Type:     pkg.YarnPkg,
		},
		"ajv": {
			Name:     "ajv",
			Version:  "6.12.3",
			Language: pkg.JavaScript,
			Type:     pkg.YarnPkg,
		},
		"atob": {
			Name:     "atob",
			Version:  "2.1.2",
			Language: pkg.JavaScript,
			Type:     pkg.YarnPkg,
		},
		"aws-sdk": {
			Name:     "aws-sdk",
			Version:  "2.706.0",
			Language: pkg.JavaScript,
			Type:     pkg.YarnPkg,
		},
		"jhipster-core": {
			Name:     "jhipster-core",
			Version:  "7.3.4",
			Language: pkg.JavaScript,
			Type:     pkg.YarnPkg,
		},
	}
	fixture, err := os.Open("test-fixtures/yarn/yarn.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseYarnLock(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse yarn.lock: %+v", err)
	}

	assertPkgsEqual(t, actual, expected)

}
