package pkg

import (
	"strings"

	"github.com/anchore/packageurl-go"
)

// Language represents a single programming language.
type Language string

const (
	// the full set of supported programming languages
	UnknownLanguage Language = ""
	Java            Language = "java"
	JavaScript      Language = "javascript"
	Python          Language = "python"
	PHP             Language = "php"
	Ruby            Language = "ruby"
	Go              Language = "go"
	Rust            Language = "rust"
	Dart            Language = "dart"
	Dotnet          Language = "dotnet"
	Swift           Language = "swift"
	CPP             Language = "c++"
	Haskell         Language = "haskell"
	Binary          Language = "binary"
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
	Dart,
	Dotnet,
	Swift,
	CPP,
	Haskell,
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

	return LanguageByName(purl.Type)
}

func LanguageByName(name string) Language {
	switch strings.ToLower(name) {
	case packageurl.TypeMaven, string(purlGradlePkgType), string(JavaPkg), string(Java):
		return Java
	case packageurl.TypeComposer, string(PhpComposerPkg), string(PHP):
		return PHP
	case packageurl.TypeGolang, string(GoModulePkg), string(Go):
		return Go
	case packageurl.TypeNPM, string(JavaScript), "nodejs", "node.js":
		return JavaScript
	case packageurl.TypePyPi, string(Python):
		return Python
	case packageurl.TypeGem, string(Ruby):
		return Ruby
	case purlCargoPkgType, string(RustPkg), string(Rust):
		return Rust
	case packageurl.TypePub, string(DartPubPkg), string(Dart):
		return Dart
	case packageurl.TypeDotnet:
		return Dotnet
	case packageurl.TypeCocoapods, packageurl.TypeSwift, string(CocoapodsPkg):
		return Swift
	case packageurl.TypeConan, string(CPP):
		return CPP
	case packageurl.TypeHackage, string(Haskell):
		return Haskell
	default:
		return UnknownLanguage
	}
}
