package source

type DirectoryMetadata struct {
	Path string `json:"path" yaml:"path"`
	Base string `json:"-" yaml:"-"` // though this is important, for display purposes it leaks too much information (abs paths)
}
