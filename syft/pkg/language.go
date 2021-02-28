package pkg

// Language represents a single programming language.
type Language string

const (
	// the full set of supported programming languages
	UnknownLanguage Language = "UnknownLanguage"
	Java            Language = "java"
	JavaScript      Language = "javascript"
	Python          Language = "python"
	Ruby            Language = "ruby"
	Go              Language = "go"
	Rust            Language = "rust"
)

// AllLanguages is a set of all programming languages detected by syft.
var AllLanguages = []Language{
	Java,
	JavaScript,
	Python,
	Ruby,
	Go,
	Rust,
}

// String returns the string representation of the language.
func (l Language) String() string {
	return string(l)
}
