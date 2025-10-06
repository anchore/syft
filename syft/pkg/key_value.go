package pkg

import (
	"encoding/json"
	"fmt"
	"sort"
)

// KeyValue represents a single key-value pair.
type KeyValue struct {
	// Key is the key name
	Key string `json:"key"`

	// Value is the value associated with the key
	Value string `json:"value"`
}

// KeyValues represents an ordered collection of key-value pairs that preserves insertion order.
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
		sort.Strings(keys)
		for _, k := range keys {
			kvs = append(kvs, KeyValue{Key: k, Value: legacyMap[k]})
		}
	}
	*k = kvs
	return nil
}
