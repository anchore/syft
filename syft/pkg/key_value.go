package pkg

import (
	"sort"
)

type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type KeyValues []KeyValue

func (k KeyValues) Get(key string) (string, bool) {
	for _, kv := range k {
		if kv.Key == key {
			return kv.Value, true
		}
	}

	return "", false
}

func (k KeyValues) MustGet(key string) string {
	for _, kv := range k {
		if kv.Key == key {
			return kv.Value
		}
	}

	return ""
}

func keyValuesFromMap(m map[string]string) KeyValues {
	var result KeyValues
	var mapKeys []string
	for k := range m {
		mapKeys = append(mapKeys, k)
	}
	sort.Strings(mapKeys)
	for _, k := range mapKeys {
		result = append(result, KeyValue{
			Key:   k,
			Value: m[k],
		})
	}
	return result
}
