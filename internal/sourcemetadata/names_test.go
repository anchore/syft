package sourcemetadata

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllNames(t *testing.T) {
	// note: this is a form of completion testing relative to the current code base.

	expected, err := DiscoverTypeNames()
	require.NoError(t, err)

	actual := AllTypeNames()

	// ensure that the codebase (from ast analysis) reflects the latest code generated state
	if !assert.ElementsMatch(t, expected, actual) {
		t.Errorf("metadata types not fully represented: \n%s", cmp.Diff(expected, actual))
		t.Log("did you add a new source.*Metadata type without updating the JSON schema?")
		t.Log("if so, you need to update the schema version and regenerate the JSON schema (make generate-json-schema)")
	}

	for _, ty := range AllTypes() {
		assert.NotEmpty(t, JSONName(ty), "metadata type %q does not have a JSON name", reflect.TypeOf(ty).Name())
	}
}
