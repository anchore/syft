package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/syft/sort"
	stdSort "sort"
)

type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (k KeyValue) Compare(other KeyValue) int {
	if i := sort.CompareOrd(k.Key, other.Key); i != 0 {
		return i
	}
	if i := sort.CompareOrd(k.Value, other.Value); i != 0 {
		return i
	}
	return 0
}

type KeyValues []KeyValue

func (k KeyValues) Compare(other KeyValues) int {
	if i := sort.CompareArrays(k, other); i != 0 {
		return i
	}
	return 0
}

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
	stdSort.Strings(mapKeys)
	for _, k := range mapKeys {
		result = append(result, KeyValue{
			Key:   k,
			Value: m[k],
		})
	}
	return result
}

func (k *KeyValues) UnmarshalJSON(b []byte) error {
	var kvs []KeyValue
	if err := json.Unmarshal(b, &kvs); err != nil {
		var legacyMap map[string]string
		if err := json.Unmarshal(b, &legacyMap); err != nil {
			return fmt.Errorf("unable to unmarshal KeyValues: %w", err)
		}
		var keys []string
		for k := range legacyMap {
			keys = append(keys, k)
		}
		stdSort.Strings(keys)
		for _, k := range keys {
			kvs = append(kvs, KeyValue{Key: k, Value: legacyMap[k]})
		}
	}
	*k = kvs
	return nil
}
