package syft

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/iancoleman/strcase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/file"
)

func Test_configurationAuditTrail_StructTags(t *testing.T) {
	// we need to ensure that the output for any configuration is well-formed and follows conventions.
	// We ensure that:
	// 1. all fields have a JSON tag
	// 2. the tag value follows lowercase kebab-case style

	jsonTags := getJSONTags(t, configurationAuditTrail{})

	for _, tag := range jsonTags {
		assertLowercaseKebab(t, tag)
	}

}

func getJSONTags(t *testing.T, v interface{}) []string {
	var tags []string
	err := collectJSONTags(t, reflect.ValueOf(v), &tags, "", "")
	require.NoError(t, err)
	return tags
}

func collectJSONTags(t *testing.T, v reflect.Value, tags *[]string, parentTag string, path string) error {
	var errs error

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return errs
	}

	tType := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := tType.Field(i)

		curPath := path + "." + fieldType.Name

		// account for embeddings
		if fieldType.Anonymous {
			embeddedField := field

			if embeddedField.Kind() == reflect.Ptr {
				// this can be enhanced in the future if the need arises...
				errs = multierror.Append(errs, fmt.Errorf("field '%s' is a pointer to an embedded struct, this is not supported in the test helper", curPath))
			}

			if embeddedField.Kind() == reflect.Struct {
				err := collectJSONTags(t, field, tags, parentTag, curPath)
				if err != nil {
					errs = multierror.Append(errs, err)
				}
			}

			continue
		}

		var tag string
		var ok bool
		if fieldType.PkgPath == "" {
			tag, ok = fieldType.Tag.Lookup("json")
			if !ok || (tag == "" && parentTag == "") {
				errs = multierror.Append(errs, fmt.Errorf("field '%s' does not have a json tag", curPath))
				return errs
			}
			if tag != "" && tag != "-" {
				*tags = append(*tags, tag)
			}
		}

		if field.Kind() == reflect.Struct || (field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct) {
			err := collectJSONTags(t, field, tags, tag, curPath)
			if err != nil {
				errs = multierror.Append(errs, err)
			}
		}
	}
	return errs
}

func assertLowercaseKebab(t *testing.T, tag string) {
	t.Helper()
	require.NotEmpty(t, tag)
	assert.Equal(t, strcase.ToKebab(tag), tag)
}

func Test_collectJSONTags(t *testing.T) {
	// though this is not used in production, this is a sensitive and complex enough of a check to warrant testing the test helper.
	type good struct {
		A string `json:"a"`
	}

	type missing struct {
		A string `json:"a"`
		B string
	}

	type exclude struct {
		A string `json:"a"`
		B string `json:"-"`
	}

	type goodEmbedded struct {
		good `json:""`
	}

	type badEmbedded struct {
		missing `json:""`
	}

	// simply not covered and require further development to support
	type goodPtrEmbedded struct {
		*good `json:""`
	}

	// simply not covered and require further development to support
	type badPtrEmbedded struct {
		*missing `json:""`
	}

	tests := []struct {
		name    string
		v       interface{}
		want    []string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "good",
			v:    good{},
			want: []string{
				"a",
			},
		},
		{
			name:    "missing",
			v:       missing{},
			wantErr: require.Error,
		},
		{
			name: "exclude",
			v:    exclude{},
			want: []string{
				"a",
			},
		},
		{
			name:    "bad embedded",
			v:       badEmbedded{},
			wantErr: require.Error,
		},
		{
			name: "good embedded",
			v:    goodEmbedded{},
			want: []string{
				"a",
			},
		},
		// these cases are simply not covered and require further development to support
		{
			name:    "bad ptr embedded",
			v:       badPtrEmbedded{},
			wantErr: require.Error,
		},
		{
			name: "good ptr embedded",
			v:    goodPtrEmbedded{},
			want: []string{
				"a",
			},
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			var tags []string

			err := collectJSONTags(t, reflect.ValueOf(tt.v), &tags, "", "")

			tt.wantErr(t, err)
			if err != nil {
				return
			}

			assert.Equal(t, tt.want, tags)
		})
	}

}

func Test_configurationAuditTrail_MarshalJSON(t *testing.T) {

	tests := []struct {
		name   string
		cfg    configurationAuditTrail
		assert func(t *testing.T, got []byte)
	}{
		{
			name: "ensure other marshallers are called",
			cfg: configurationAuditTrail{

				Files: filecataloging.Config{
					Selection: file.FilesOwnedByPackageSelection,
					Hashers: []crypto.Hash{
						crypto.SHA256,
					},
				},
			},
			// the custom file marshaller swaps ints for strings for hashers
			assert: func(t *testing.T, got []byte) {
				assert.Contains(t, string(got), `"hashers":["sha-256"]`)
			},
		},
		{
			name: "ensure maps are sorted",
			cfg:  configurationAuditTrail{},
			assert: func(t *testing.T, got []byte) {
				assert.NoError(t, assertJSONKeysSorted(got))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := tt.cfg.MarshalJSON()
			require.NoError(t, err)
			if tt.assert == nil {
				t.Fatal("assert function must be provided")
			}
			tt.assert(t, got)

		})
	}
}

// assertJSONKeysSorted asserts that all keys in JSON maps are sorted.
func assertJSONKeysSorted(jsonBytes []byte) error {
	var errs error
	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	var keys []string
	var inObject bool

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			errs = multierror.Append(errs, fmt.Errorf("error decoding JSON: %w", err))
		}

		switch v := token.(type) {
		case json.Delim:
			switch v {
			case '{':
				inObject = true
				keys = nil // Reset keys for a new object
			case '}':
				inObject = false
				if !sort.StringsAreSorted(keys) {
					errs = multierror.Append(errs, fmt.Errorf("Keys are not sorted: %v", keys))
				}
			}
		case string:
			if inObject && v != "" {
				keys = append(keys, v)
			}
		}
	}
	return errs
}

func Test_assertJSONKeysSorted(t *testing.T) {
	// this test function is sufficiently complicated enough to warrant its own test...

	sorted := []byte(`{"a":1,"b":2}`)
	unsorted := []byte(`{"b":2,"a":1}`)

	nestedSorted := []byte(`{"a":1,"b":{"a":1,"b":2}}`)
	nestedUnsorted := []byte(`{"a":1,"b":{"b":2,"a":1}}`)

	tests := []struct {
		name    string
		json    []byte
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "sorted",
			json:    sorted,
			wantErr: require.NoError,
		},
		{
			name:    "unsorted",
			json:    unsorted,
			wantErr: require.Error,
		},
		{
			name:    "nested sorted",
			json:    nestedSorted,
			wantErr: require.NoError,
		},
		{
			name:    "nested unsorted",
			json:    nestedUnsorted,
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			err := assertJSONKeysSorted(tt.json)
			tt.wantErr(t, err)
		})

	}
}
