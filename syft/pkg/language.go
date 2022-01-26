package pkg

import "github.com/anchore/packageurl-go"

// Language represents a single programming language.
type Language string

const (
	// the full set of supported programming languages
	UnknownLanguage Language = "UnknownLanguage"
	Java            Language = "java"
	JavaScript      Language = "javascript"
	Python          Language = "python"
	PHP             Language = "php"
	Ruby            Language = "ruby"
	Go              Language = "go"
	Rust            Language = "rust"
)

const (
	Cargo string = "cargo"
)

// AllLanguages is a set of all programming languages detected by syft.
var AllLanguages = []Language{
	Java,
	JavaScript,
	Python,
	PHP,
	Ruby,
	Go,
	Rust,
}

// String returns the string representation of the language.
func (l Language) String() string {
	return string(l)
}

func LanguageFromPURL(p string) Language {
	purl, err := packageurl.FromString(p)
	if err != nil {
		return UnknownLanguage
	}

	switch purl.Type {
	case packageurl.TypeMaven, "gradle":
		return Java
	case packageurl.TypeComposer:
		return PHP
	case packageurl.TypeGolang:
		return Go
	case packageurl.TypeNPM:
		return JavaScript
	case packageurl.TypePyPi:
		return Python
	case packageurl.TypeGem:
		return Ruby
	case Cargo:
		return Rust
	default:
		return UnknownLanguage
	}
}
