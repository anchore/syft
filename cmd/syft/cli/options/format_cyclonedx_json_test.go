package options

import (
	"reflect"
	"testing"
)

func TestFormatCyclonedxJSON_buildConfig(t *testing.T) {
	// assert when building the config that we respond to all possible fields

	ft := FormatCyclonedxJSON{}
	ftp := setAllToNonZero(t, &ft).(*FormatCyclonedxJSON)

	subject := ftp.buildConfig("1.2")
	assertNoZeroFields(t, subject)
}

func setAllToNonZero(t testing.TB, structPtr any) any {
	// set all fields on the struct to non-zero values
	rt := reflect.TypeOf(structPtr)
	if rt.Kind() != reflect.Ptr || rt.Elem().Kind() != reflect.Struct {
		t.Fatal("expected a pointer to a struct")
	}

	rv := reflect.ValueOf(structPtr).Elem()
	for i := 0; i < rt.Elem().NumField(); i++ {
		//f := rt.Elem().Field(i)
		val := getNonZeroExampleValue(t, rv.Field(i).Interface())
		rv.Field(i).Set(reflect.ValueOf(val))
	}
	return structPtr
}

func getNonZeroExampleValue(t testing.TB, v any) any {
	switch v.(type) {
	case bool:
		return true
	case string:
		return "foo"
	}
	t.Fatalf("unsupported type: %T", v)
	return nil
}

func assertNoZeroFields(t *testing.T, structTy any) {
	rt := reflect.TypeOf(structTy)
	rv := reflect.ValueOf(structTy)

	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		fieldValue := rv.Field(i)

		if reflect.DeepEqual(fieldValue.Interface(), reflect.Zero(fieldValue.Type()).Interface()) {
			t.Errorf("field '%s' is zero", f.Name)
		}
	}
}
