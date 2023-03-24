package pkg

type FileMetadata struct {
	Classifier  string `mapstructure:"Classifier" json:"classifier"`
	RealPath    string `mapstructure:"RealPath" json:"realPath"`
	VirtualPath string `mapstructure:"VirtualPath" json:"virtualPath"`
}
