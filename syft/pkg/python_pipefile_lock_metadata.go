package pkg

type PythonPipfileLockMetadata struct {
	Hashes []string `mapstructure:"hashes" json:"hashes"`
	Index  string   `mapstructure:"index" json:"index"`
}
