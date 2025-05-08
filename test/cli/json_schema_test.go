package cli

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/internal"
)

// this is the path to the json schema directory relative to the root of the repo
const jsonSchemaPath = "schema/json"

func TestJSONSchema(t *testing.T) {

	imageFixture := func(t *testing.T) string {
		fixtureImageName := "image-pkg-coverage"
		imagetest.GetFixtureImage(t, "docker-archive", fixtureImageName)
		tarPath := imagetest.GetFixtureImageTarPath(t, fixtureImageName)
		return "docker-archive:" + tarPath
	}

	tests := []struct {
		name       string
		subcommand string
		args       []string
		fixture    func(*testing.T) string
	}{
		{
			name:       "scan:image:docker-archive:pkg-coverage",
			subcommand: "scan",
			args:       []string{"-o", "json"},
			fixture:    imageFixture,
		},
		{
			name:       "scan:dir:pkg-coverage",
			subcommand: "scan",
			args:       []string{"-o", "json"},
			fixture: func(t *testing.T) string {
				return "dir:test-fixtures/image-pkg-coverage"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixtureRef := test.fixture(t)
			args := []string{
				test.subcommand, fixtureRef, "-q",
			}
			args = append(args, test.args...)

			_, stdout, stderr := runSyft(t, nil, args...)

			if len(strings.Trim(stdout, "\n ")) < 100 {
				t.Fatalf("bad syft run:\noutput: %q\n:error: %q", stdout, stderr)
			}

			validateJsonAgainstSchema(t, stdout)
		})
	}
}

func validateJsonAgainstSchema(t testing.TB, json string) {
	t.Helper()
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
