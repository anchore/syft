package main

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/schema/json/internal"
)

func TestAllMetadataRepresented(t *testing.T) {
	// this test checks that all the metadata types are represented in the currently generated ArtifactMetadataContainer struct
	// such that PRs will reflect when there is drift from the implemented set of metadata types and the generated struct
	// which controls the JSON schema content.
	expected, err := internal.AllSyftMetadataTypeNames()
	require.NoError(t, err)
	actual := allTypeNamesFromStruct(internal.ArtifactMetadataContainer{})
	if !assert.ElementsMatch(t, expected, actual) {
		t.Errorf("metadata types not fully represented: \n%s", cmp.Diff(expected, actual))
		t.Log("did you add a new pkg.*Metadata type without updating the JSON schema?")
		t.Log("if so, you need to update the schema version and regenerate the JSON schema (make generate-json-schema)")
	}
}

func allTypeNamesFromStruct(instance any) []string {
	// get all the type names from the struct (not recursively)
	var typeNames []string
	tt := reflect.TypeOf(instance)
	for i := 0; i < tt.NumField(); i++ {
		field := tt.Field(i)
		typeNames = append(typeNames, field.Type.Name())
	}
	sort.Strings(typeNames)
	return typeNames
}
