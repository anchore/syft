package integration

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/presenter"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
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
	fullSchemaPath := path.Join(repoRoot(t), jsonSchemaPath, fmt.Sprintf("schema-%s.json", internal.JSONSchemaVersion))
	schemaLoader := gojsonschema.NewReferenceLoader(fmt.Sprintf("file://%s", fullSchemaPath))
	documentLoader := gojsonschema.NewStringLoader(json)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		t.Fatal("unable to validate json schema:", err.Error())
	}

	if !result.Valid() {
		t.Errorf("failed json schema validation:")
		t.Errorf("JSON:\n%s\n", json)
		for _, desc := range result.Errors() {
			t.Errorf("  - %s\n", desc)
		}
	}
}

func TestJsonSchemaImg(t *testing.T) {
	fixtureImageName := "image-pkg-coverage"
	_, cleanup := imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
	defer cleanup()

	src, catalog, _, err := syft.Catalog("docker-archive:"+tarPath, source.SquashedScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	output := bytes.NewBufferString("")

	d, err := distro.NewDistro(distro.CentOS, "5", "rhel fedora")
	if err != nil {
		t.Fatalf("bad distro: %+v", err)
	}

	p := presenter.GetPresenter(presenter.JSONPresenter, src.Metadata, catalog, &d)
	if p == nil {
		t.Fatal("unable to get presenter")
	}

	err = p.Present(output)
	if err != nil {
		t.Fatalf("unable to present: %+v", err)
	}

	validateAgainstV1Schema(t, output.String())

}

func TestJsonSchemaDirs(t *testing.T) {
	src, catalog, _, err := syft.Catalog("dir:test-fixtures/image-pkg-coverage", source.SquashedScope)
	if err != nil {
		t.Errorf("unable to create source from dir: %+v", err)
	}

	output := bytes.NewBufferString("")

	d, err := distro.NewDistro(distro.CentOS, "5", "rhel fedora")
	if err != nil {
		t.Fatalf("bad distro: %+v", err)
	}

	p := presenter.GetPresenter(presenter.JSONPresenter, src.Metadata, catalog, &d)
	if p == nil {
		t.Fatal("unable to get presenter")
	}

	err = p.Present(output)
	if err != nil {
		t.Fatalf("unable to present: %+v", err)
	}

	validateAgainstV1Schema(t, output.String())
}
