package pkg

type LuaRocksPackage struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	License      string            `json:"license"`
	Homepage     string            `json:"homepage"`
	Description  string            `json:"description"`
	URL          string            `json:"url"`
	Dependencies map[string]string `json:"dependencies"`
}
