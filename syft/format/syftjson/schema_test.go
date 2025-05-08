package syftjson

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/iancoleman/strcase"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/packagemetadata"
)

type schema struct {
	Schema string                `json:"$schema"`
	ID     string                `json:"$id"`
	Ref    string                `json:"$ref"`
	Defs   map[string]properties `json:"$defs"`
}

type properties struct {
	Properties map[string]any `json:"properties"`
	Type       string         `json:"type"`
	Required   []string       `json:"required"`
}

func (p properties) fields() []string {
	var result []string

	for k := range p.Properties {
		result = append(result, k)
	}
	return result
}

func Test_JSONSchemaConventions(t *testing.T) {
	// read schema/json/schema-latest.json
	// look at all attributes and ensure that all fields are camelCase
	// we want to strictly follow https://google.github.io/styleguide/javaguide.html#s5.3-camel-case
	//
	// > Convert the phrase to plain ASCII and remove any apostrophes. For example, "Müller's algorithm" might become "Muellers algorithm".
	// > Divide this result into words, splitting on spaces and any remaining punctuation (typically hyphens).
	// > Recommended: if any word already has a conventional camel-case appearance in common usage, split this into its constituent parts (e.g., "AdWords" becomes "ad words"). Note that a word such as "iOS" is not really in camel case per se; it defies any convention, so this recommendation does not apply.
	// > Now lowercase everything (including acronyms), then uppercase only the first character of:
	// > ... each word, to yield upper camel case, or
	// > ... each word except the first, to yield lower camel case
	// > Finally, join all the words into a single identifier.
	//
	// This means that acronyms should be treated as words (e.g. "HttpServer" not "HTTPServer")

	root, err := packagemetadata.RepoRoot()
	require.NoError(t, err)

	contents, err := os.ReadFile(filepath.Join(root, "schema", "json", "schema-latest.json"))
	require.NoError(t, err)

	var s schema
	require.NoError(t, json.Unmarshal(contents, &s))

	require.NotEmpty(t, s.Defs)

	for name, def := range s.Defs {
		checkAndConvertFields(t, name, def.fields())
	}
}

func checkAndConvertFields(t *testing.T, path string, properties []string) {
	for _, fieldName := range properties {
		if pass, exp := isFollowingConvention(path, fieldName); !pass {
			t.Logf("%s: has non camel case field: %q (expected %q)", path, fieldName, exp)
		}

	}
}

func isFollowingConvention(path, fieldName string) (bool, string) {
	exp := strcase.ToLowerCamel(fieldName)
	result := exp == fieldName

	exception := func(exceptions ...string) (bool, string) {
		for _, e := range exceptions {
			if e == fieldName {
				return true, fieldName
			}
		}
		return result, exp
	}

	// add exceptions as needed... these are grandfathered in and will be addressed in a future breaking schema change
	// ideally in the future there will be no exceptions to the camel case convention for fields
	switch path {
	case "Coordinates", "Location":
		return exception("layerID")
	case "MicrosoftKbPatch":
		return exception("product_id")
	case "HaskellHackageStackLockEntry":
		return exception("snapshotURL")
	case "LinuxRelease":
		return exception("imageID", "supportURL", "privacyPolicyURL", "versionID", "variantID", "homeURL", "buildID", "bugReportURL")
	case "CConanLockV2Entry":
		return exception("packageID")
	case "CConanInfoEntry":
		return exception("package_id")
	case "PhpComposerInstalledEntry", "PhpComposerLockEntry":
		return exception("notification-url", "require-dev")
	case "LinuxKernelArchive":
		return exception("rwRootFS")
	case "CConanLockEntry":
		return exception("build_requires", "py_requires", "package_id")
	case "FileMetadataEntry":
		return exception("userID", "groupID")
	case "DartPubspecLockEntry":
		return exception("hosted_url", "vcs_url")
	case "ELFSecurityFeatures":
		return exception("relRO")
	}
	return result, exp
}
