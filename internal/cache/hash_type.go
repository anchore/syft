package cache

import (
	"fmt"
	"reflect"

	"github.com/gohugoio/hashstructure"
)

// hashType returns a stable hash based on the structure of the type
func hashType[T any]() string {
	// get the base type and hash an empty instance
	var t T
	empty := emptyValue(reflect.TypeOf(t)).Interface()
	hash, err := hashstructure.Hash(empty, &hashstructure.HashOptions{
		ZeroNil:         false,
		IgnoreZeroValue: false,
		SlicesAsSets:    false,
		UseStringer:     false,
	})
	if err != nil {
		panic(fmt.Errorf("unable to use type as cache key: %w", err))
	}
	return fmt.Sprintf("%x", hash)
}

func emptyValue(t reflect.Type) reflect.Value {
	switch t.Kind() {
	case reflect.Pointer:
		e := t.Elem()
		v := emptyValue(e)
		if v.CanAddr() {
			return v.Addr()
		}
		ptrv := reflect.New(e)
		ptrv.Elem().Set(v)
		return ptrv
	case reflect.Slice:
		v := emptyValue(t.Elem())
		s := reflect.MakeSlice(t, 1, 1)
		s.Index(0).Set(v)
		return s
	case reflect.Struct:
		v := reflect.New(t).Elem()
		// get all empty field values, too
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if isIgnored(f) {
				continue
			}
			fv := v.Field(i)
			if fv.CanSet() {
				fv.Set(emptyValue(f.Type))
			}
		}
		return v
	default:
		return reflect.New(t).Elem()
	}
}

func isIgnored(f reflect.StructField) bool {
	if !f.IsExported() {
		return true
	}
	tag := f.Tag.Get("hash")
	if tag == "-" || tag == "ignore" {
		return true
	}
	return false
}
