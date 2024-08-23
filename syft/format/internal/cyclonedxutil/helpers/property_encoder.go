package helpers

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal/log"
)

// FieldName return a flag to indicate this is a valid field and a name to use
type FieldName func(field reflect.StructField) (string, bool)

// OptionalTag given a tag name, will return the defined tag or fall back to lower camel case field name
func OptionalTag(tag string) FieldName {
	return func(f reflect.StructField) (string, bool) {
		if n, ok := f.Tag.Lookup(tag); ok {
			return n, true
		}
		return lowerFirst(f.Name), true
	}
}

// TrimOmitempty trims `,omitempty` from the name
func TrimOmitempty(fn FieldName) FieldName {
	return func(f reflect.StructField) (string, bool) {
		if v, ok := fn(f); ok {
			return strings.TrimSuffix(v, ",omitempty"), true
		}
		return "", false
	}
}

// RequiredTag based on the given tag, only use a field if present
func RequiredTag(tag string) FieldName {
	return func(f reflect.StructField) (string, bool) {
		if n, ok := f.Tag.Lookup(tag); ok {
			return n, true
		}
		return "", false
	}
}

var (
	// OptionalJSONTag uses field names defined in json tags, if available
	OptionalJSONTag = TrimOmitempty(OptionalTag("json"))
)

// lowerFirst converts the first character of the string to lower case
func lowerFirst(s string) string {
	return strings.ToLower(s[0:1]) + s[1:]
}

// Encode recursively encodes the object's properties as an ordered set of NameValue pairs
func Encode(obj interface{}, prefix string, fn FieldName) map[string]string {
	if obj == nil {
		return nil
	}
	props := map[string]string{}
	encode(props, reflect.ValueOf(obj), prefix, fn)
	return props
}

// NameValue a simple type to store stringified name/value pairs
type NameValue struct {
	Name  string
	Value string
}

// Sorted returns a sorted set of NameValue pairs
func Sorted(values map[string]string) (out []NameValue) {
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, NameValue{
			Name:  k,
			Value: values[k],
		})
	}
	return
}

func encode(out map[string]string, value reflect.Value, prefix string, fn FieldName) {
	if !value.IsValid() || value.Type() == nil {
		return
	}

	typ := value.Type()

	switch typ.Kind() {
	case reflect.Ptr:
		if value.IsNil() {
			return
		}
		value = value.Elem()
		encode(out, value, prefix, fn)
	case reflect.String:
		v := value.String()
		if v != "" {
			out[prefix] = v
		}
	case reflect.Bool:
		v := value.Bool()
		out[prefix] = strconv.FormatBool(v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v := value.Int()
		out[prefix] = strconv.FormatInt(v, 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v := value.Uint()
		out[prefix] = strconv.FormatUint(v, 10)
	case reflect.Float32, reflect.Float64:
		v := value.Float()
		out[prefix] = fmt.Sprintf("%f", v)
	case reflect.Array, reflect.Slice:
		for idx := 0; idx < value.Len(); idx++ {
			encode(out, value.Index(idx), fmt.Sprintf("%s:%d", prefix, idx), fn)
		}
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			pv := value.Field(i)
			f := typ.Field(i)
			name, ok := fieldName(f, prefix, fn)
			if !ok {
				continue
			}
			encode(out, pv, name, fn)
		}
	case reflect.Map:
		// currently only map[string]string is really supported
		for _, key := range value.MapKeys() {
			encode(out, value.MapIndex(key), fmt.Sprintf("%s:%v", prefix, key.Interface()), fn)
		}
	default:
		log.Warnf("skipping encoding of unsupported property: %s", prefix)
	}
}

// fieldName gets the name of the field using the provided FieldName function
func fieldName(f reflect.StructField, prefix string, fn FieldName) (string, bool) {
	name, ok := fn(f)
	if !ok {
		return "", false
	}
	if name == "" {
		return prefix, true
	}
	if prefix != "" {
		name = fmt.Sprintf("%s:%s", prefix, name)
	}
	return name, true
}

// Decode based on the given type, applies all values to hydrate a new instance
func Decode(typ reflect.Type, values map[string]string, prefix string, fn FieldName) interface{} {
	isPtr := false
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
		isPtr = true
	}

	isSlice := false
	if typ.Kind() == reflect.Slice {
		typ = reflect.PointerTo(typ)
		isSlice = true
	}

	v := reflect.New(typ)

	decode(values, v, prefix, fn)

	switch {
	case isSlice && isPtr:
		return v.Elem().Interface()
	case isSlice:
		return PtrToStruct(v.Elem().Interface())
	case isPtr:
		return v.Interface()
	}
	return v.Elem().Interface()
}

// DecodeInto decodes all values to hydrate the given object instance
func DecodeInto(obj interface{}, values map[string]string, prefix string, fn FieldName) {
	value := reflect.ValueOf(obj)

	for value.Type().Kind() == reflect.Ptr {
		value = value.Elem()
	}

	decode(values, value, prefix, fn)
}

//nolint:funlen,gocognit,gocyclo
func decode(vals map[string]string, value reflect.Value, prefix string, fn FieldName) bool {
	if !value.IsValid() || value.Type() == nil {
		return false
	}

	typ := value.Type()

	incoming, valid := vals[prefix]
	switch typ.Kind() {
	case reflect.Ptr:
		t := typ.Elem()
		v := value
		if v.IsNil() {
			v = reflect.New(t)
		}
		if decode(vals, v.Elem(), prefix, fn) && value.CanSet() {
			o := v.Interface()
			log.Infof("%v", o)
			value.Set(v)
		} else {
			return false
		}
	case reflect.String:
		if valid {
			value.SetString(incoming)
		} else {
			return false
		}
	case reflect.Bool:
		if !valid {
			return false
		}
		if b, err := strconv.ParseBool(incoming); err == nil {
			value.SetBool(b)
		} else {
			return false
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if !valid {
			return false
		}
		if i, err := strconv.ParseInt(incoming, 10, 64); err == nil {
			value.SetInt(i)
		} else {
			return false
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if !valid {
			return false
		}
		if i, err := strconv.ParseUint(incoming, 10, 64); err == nil {
			value.SetUint(i)
		} else {
			return false
		}
	case reflect.Float32, reflect.Float64:
		if !valid {
			return false
		}
		if i, err := strconv.ParseFloat(incoming, 64); err == nil {
			value.SetFloat(i)
		} else {
			return false
		}
	case reflect.Array, reflect.Slice:
		values := false
		t := typ.Elem()
		slice := reflect.MakeSlice(typ, 0, 0)
		for idx := 0; ; idx++ {
			// test for index
			str := fmt.Sprintf("%s:%d", prefix, idx)
			// create new placeholder and decode values
			newType := t
			if t.Kind() == reflect.Ptr {
				newType = t.Elem()
			}
			v := reflect.New(newType)
			if decode(vals, v.Elem(), str, fn) {
				// append to slice
				if t.Kind() != reflect.Ptr {
					v = v.Elem()
				}
				slice = reflect.Append(slice, v)
				values = true
			} else {
				break
			}
		}
		if values {
			value.Set(slice)
		} else {
			return false
		}
	case reflect.Map:
		values := false
		keyType := typ.Key()
		valueType := typ.Elem()
		outMap := reflect.MakeMap(typ)
		str := fmt.Sprintf("%s:", prefix)
		keyVals := map[string]string{}
		// iterate through all keys to find those prefixed with a reference to this map
		// NOTE: this will not work for nested maps
		for key := range vals {
			// test for map prefix
			if strings.HasPrefix(key, str) {
				keyVals[key] = strings.TrimPrefix(key, str)
				// create new placeholder and decode key
				newKeyType := keyType
				if keyType.Kind() == reflect.Ptr {
					newKeyType = keyType.Elem()
				}
				k := reflect.New(newKeyType)
				if !decode(keyVals, k.Elem(), key, fn) {
					log.Debugf("unable to decode key for: %s", key)
					continue
				}
				if keyType.Kind() != reflect.Ptr {
					k = k.Elem()
				}

				// create new placeholder and decode value
				newValueType := valueType
				if valueType.Kind() == reflect.Ptr {
					newValueType = valueType.Elem()
				}
				v := reflect.New(newValueType)
				if decode(vals, v.Elem(), key, fn) {
					if valueType.Kind() != reflect.Ptr {
						v = v.Elem()
					}

					// set in map
					outMap.SetMapIndex(k, v)
					values = true
				}
			}
		}
		if values {
			value.Set(outMap)
		} else {
			return false
		}
	case reflect.Struct:
		values := false
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			v := value.Field(i)

			name, ok := fieldName(f, prefix, fn)
			if !ok {
				continue
			}

			if decode(vals, v, name, fn) {
				values = true
			}
		}
		return values
	default:
		log.Warnf("unable to set field: %s", prefix)
		return false
	}
	return true
}

func PtrToStruct(ptr interface{}) interface{} {
	v := reflect.ValueOf(ptr)
	if v.IsZero() && v.Type().Kind() != reflect.Struct {
		return nil
	}
	switch v.Type().Kind() {
	case reflect.Ptr:
		return PtrToStruct(v.Elem().Interface())
	case reflect.Interface:
		return PtrToStruct(v.Elem().Interface())
	}
	return v.Interface()
}
