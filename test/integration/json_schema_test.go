// +build integration

package integration

import (
	"bytes"
	"fmt"
	"os"
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
	"github.com/anchore/syft/syft/scope"
	"github.com/xeipuuv/gojsonschema"
)

const jsonSchemaPath = "schema/json"
const jsonSchemaExamplesPath = jsonSchemaPath + "/examples"

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

func testJsonSchema(t *testing.T, catalog *pkg.Catalog, theScope *scope.Scope, prefix string) {
	// make the json output example dir if it does not exist
	absJsonSchemaExamplesPath := path.Join(repoRoot(t), jsonSchemaExamplesPath)
	if _, err := os.Stat(absJsonSchemaExamplesPath); os.IsNotExist(err) {
		os.Mkdir(absJsonSchemaExamplesPath, 0755)
	}

	output := bytes.NewBufferString("")

	d, err := distro.NewDistro(distro.CentOS, "5")
	if err != nil {
		t.Fatalf("bad distro: %+v", err)
	}

	p := presenter.GetPresenter(presenter.JSONPresenter, *theScope, catalog, &d)
	if p == nil {
		t.Fatal("unable to get presenter")
	}

	err = p.Present(output)
	if err != nil {
		t.Fatalf("unable to present: %+v", err)
	}

	// we use the examples dir as a way to use integration tests to drive what valid examples are in case we
	// want to update the json schema. We do not want to validate the output of the presentation format as the
	// contents may change regularly, making the integration tests brittle.
	testFileName := prefix + "_" + path.Base(t.Name()) + ".json"
	testFilePath := path.Join(absJsonSchemaExamplesPath, testFileName)

	fh, err := os.OpenFile(testFilePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatalf("unable to open json example path: %+v", err)
	}
	_, err = fh.WriteString(output.String())
	if err != nil {
		t.Fatalf("unable to write json example: %+v", err)
	}

	validateAgainstV1Schema(t, output.String())
}

func TestJsonSchemaImg(t *testing.T) {
	fixtureImageName := "image-pkg-coverage"
	_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
	defer cleanup()

	catalog, theScope, _, err := syft.Catalog("docker-archive:"+tarPath, scope.AllLayersScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, imageOnlyTestCases...)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testJsonSchema(t, catalog, theScope, "img")
		})
	}
}

func TestJsonSchemaDirs(t *testing.T) {
	catalog, theScope, _, err := syft.Catalog("dir:test-fixtures/image-pkg-coverage", scope.AllLayersScope)
	if err != nil {
		t.Errorf("unable to create scope from dir: %+v", err)
	}

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, dirOnlyTestCases...)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testJsonSchema(t, catalog, theScope, "dir")
		})
	}
}
