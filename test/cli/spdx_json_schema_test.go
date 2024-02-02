package cli

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

// this is the path to the json schema directory relative to the root of the repo
const spdxJsonSchemaPath = "schema/spdx-json"

func TestSPDXJSONSchema(t *testing.T) {
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
			args:       []string{"-o", "spdx-json"},
			fixture:    imageFixture,
		},
		{
			name:       "scan:dir:pkg-coverage",
			subcommand: "scan",
			args:       []string{"-o", "spdx-json"},
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

			_, stdout, _ := runSyft(t, nil, args...)

			if len(strings.Trim(stdout, "\n ")) < 100 {
				t.Fatalf("bad syft output: %q", stdout)
			}

			validateSpdxJsonAgainstSchema(t, stdout)
		})
	}
}

func validateSpdxJsonAgainstSchema(t testing.TB, json string) {
	fullSchemaPath := path.Join(repoRoot(t), spdxJsonSchemaPath, fmt.Sprintf("spdx-schema-2.3.json"))
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
