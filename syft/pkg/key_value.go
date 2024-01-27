package pkg

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
