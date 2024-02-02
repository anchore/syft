package options

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatCyclonedxJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := &FormatCyclonedxJSON{}
	ft = setAllToNonZero(t, ft).(*FormatCyclonedxJSON)

	subject := ft.config("Version")
	assertExpectedValue(t, subject)
}

func setAllToNonZero(t testing.TB, structPtr any) any {
	// set all fields on the struct to non-zero values
	rt := reflect.TypeOf(structPtr)
	if rt.Kind() != reflect.Ptr || rt.Elem().Kind() != reflect.Struct {
		t.Fatal("expected a pointer to a struct")
	}

	rv := reflect.ValueOf(structPtr).Elem()
	for i := 0; i < rt.Elem().NumField(); i++ {
		val := getNonZeroExampleValue(t, rv.Field(i).Interface(), rt.Elem().Field(i).Name)
		rv.Field(i).Set(reflect.ValueOf(val))
	}
	return structPtr
}

func getNonZeroExampleValue(t testing.TB, v any, name string) any {
	switch v.(type) {
	case bool:
		return true
	case *bool:
		val := true
		return &val
	case string:
		return name
	}
	t.Fatalf("unsupported type: %T", v)
	return nil
}

func assertExpectedValue(t *testing.T, structTy any) {
	rt := reflect.TypeOf(structTy)
	rv := reflect.ValueOf(structTy)

	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		fieldValue := rv.Field(i)

		if fieldValue.Type().Kind() == reflect.String {
			// use the field name as the expected value
			assert.Equalf(t, f.Name, fieldValue.String(), "field %q value differs", f.Name)
		} else {
			// use the zero value for the type
			if reflect.DeepEqual(fieldValue.Interface(), reflect.Zero(fieldValue.Type()).Interface()) {
				t.Errorf("field '%s' is zero", f.Name)
			}
		}
	}
}
