package pkg

type LuaRockPackage struct {
	Name         string
	Version      string
	License      string
	Homepage     string
	Description  string
	URL          string
	Dependencies map[string]string
}
