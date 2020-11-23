package integration

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/presenter"
	"github.com/anchore/syft/syft/source"
	"github.com/xeipuuv/gojsonschema"
)

const jsonSchemaPath = "schema/json"

func repoRoot(t *testing.T) string {
	t.Helper()
	repoRoot, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(repoRoot)))
	if err != nil {
		t.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}

func validateAgainstV1Schema(t *testing.T, json string) {
	fullSchemaPath := path.Join(repoRoot(t), jsonSchemaPath, "schema.json")
	schemaLoader := gojsonschema.NewReferenceLoader(fmt.Sprintf("file://%s", fullSchemaPath))
	documentLoader := gojsonschema.NewStringLoader(json)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		t.Fatal("unable to validate json schema:", err.Error())
	}

	if !result.Valid() {
		t.Errorf("failed json schema validation:")
		for _, desc := range result.Errors() {
			t.Errorf("  - %s\n", desc)
		}
	}
}

func testJsonSchema(t *testing.T, catalog *pkg.Catalog, theScope source.Source, prefix string) {

	output := bytes.NewBufferString("")

	d, err := distro.NewDistro(distro.CentOS, "5", "rhel fedora")
	if err != nil {
		t.Fatalf("bad distro: %+v", err)
	}

	p := presenter.GetPresenter(presenter.JSONPresenter, theScope.Metadata, catalog, &d)
	if p == nil {
		t.Fatal("unable to get presenter")
	}

	err = p.Present(output)
	if err != nil {
		t.Fatalf("unable to present: %+v", err)
	}

	validateAgainstV1Schema(t, output.String())
}

func TestJsonSchemaImg(t *testing.T) {
	fixtureImageName := "image-pkg-coverage"
	_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
	defer cleanup()

	src, catalog, _, err := syft.Catalog("docker-archive:"+tarPath, source.AllLayersScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, imageOnlyTestCases...)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testJsonSchema(t, catalog, src, "img")
		})
	}
}

func TestJsonSchemaDirs(t *testing.T) {
	src, catalog, _, err := syft.Catalog("dir:test-fixtures/image-pkg-coverage", source.AllLayersScope)
	if err != nil {
		t.Errorf("unable to create source from dir: %+v", err)
	}

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, dirOnlyTestCases...)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testJsonSchema(t, catalog, src, "dir")
		})
	}
}
