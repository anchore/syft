package rust

type dependencyInformation struct {
	Name          string                            `json:"name"`
	Version       string                            `json:"vers"`
	Dependencies  []dependencyDependencyInformation `json:"deps"`
	Checksum      string                            `json:"cksum"`
	Features      map[string]string                 `json:"features"`
	Yanked        bool                              `json:"yanked"`
	Links         string                            `json:"links"`
	StructVersion int                               `json:"v"`
	Features2     map[string]string                 `json:"features2"`
	RustVersion   string                            `json:"rust_version"`
}
type dependencyDependencyInformation struct {
	Name           string   `json:"name"`
	Requirement    string   `json:"req"`
	Features       []string `json:"features"`
	Optional       bool     `json:"optional"`
	DefaultTargets bool     `json:"default_targets"`
	Target         string   `json:"target"`
	Kind           string   `json:"kind"`
	Registry       string   `json:"registry"`
	Package        string   `json:"package"`
}
