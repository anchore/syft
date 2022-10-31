package pkg

type BinaryMetadata struct {
	Classifier  string `mapstructure:"Classifier" json:"classifier"`
	RealPath    string `mapstructure:"RealPath" json:"realPath"`
	VirtualPath string `mapstructure:"VirtualPath" json:"virtualPath"`
}
