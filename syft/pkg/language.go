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
	CPP             Language = "c++"
	Dart            Language = "dart"
	Dotnet          Language = "dotnet"
	Elixir          Language = "elixir"
	Erlang          Language = "erlang"
	Go              Language = "go"
	Haskell         Language = "haskell"
	Java            Language = "java"
	JavaScript      Language = "javascript"
	PHP             Language = "php"
	Python          Language = "python"
	R               Language = "R"
	Ruby            Language = "ruby"
	Rust            Language = "rust"
	Swift           Language = "swift"
)

// AllLanguages is a set of all programming languages detected by syft.
var AllLanguages = []Language{
	CPP,
	Dart,
	Dotnet,
	Elixir,
	Erlang,
	Go,
	Haskell,
	Java,
	JavaScript,
	PHP,
	Python,
	R,
	Ruby,
	Rust,
	Swift,
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
	case string(Dotnet), ".net", packageurl.TypeNuget:
		return Dotnet
	case packageurl.TypeCocoapods, packageurl.TypeSwift, string(CocoapodsPkg), string(SwiftPkg):
		return Swift
	case packageurl.TypeConan, string(CPP):
		return CPP
	case packageurl.TypeHackage, string(Haskell):
		return Haskell
	case packageurl.TypeHex, packageurl.TypeOTP, "beam", "elixir", "erlang":
		// should we support returning multiple languages to support this case?
		// answer: no. We want this to definitively answer "which language does this package represent?"
		// which might not be possible in all cases. See for more context: https://github.com/package-url/purl-spec/pull/178
		return UnknownLanguage
	case packageurl.TypeCran, "r":
		return R
	default:
		return UnknownLanguage
	}
}
