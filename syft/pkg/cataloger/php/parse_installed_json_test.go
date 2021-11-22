package php

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseInstalledJsonComposerV1(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:     "asm89/stack-cors",
			Version:  "1.3.0",
			Language: pkg.PHP,
			Type:     pkg.PhpComposerPkg,
		},
		{
			Name:     "behat/mink",
			Version:  "v1.8.1",
			Language: pkg.PHP,
			Type:     pkg.PhpComposerPkg,
		},
	}
	fixture, err := os.Open("test-fixtures/vendor/composer_1/installed.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseInstalledJson(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}
	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}

}

func TestParseInstalledJsonComposerV2(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:     "asm89/stack-cors",
			Version:  "1.3.0",
			Language: pkg.PHP,
			Type:     pkg.PhpComposerPkg,
		},
		{
			Name:     "behat/mink",
			Version:  "v1.8.1",
			Language: pkg.PHP,
			Type:     pkg.PhpComposerPkg,
		},
	}
	fixture, err := os.Open("test-fixtures/vendor/composer_2/installed.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseInstalledJson(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}
	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}

}
