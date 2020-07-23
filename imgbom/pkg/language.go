package pkg

const (
	UnknownLanguage Language = iota
	Java
	JavaScript
	Python
	Ruby
	Go
)

type Language uint

var languageStr = []string{
	"UnknownLanguage",
	"java",
	"javascript",
	"python",
	"ruby",
	"go",
}

var AllLanguages = []Language{
	Java,
	JavaScript,
	Python,
	Ruby,
	Go,
}

func (t Language) String() string {
	if int(t) >= len(languageStr) {
		return languageStr[0]
	}
	return languageStr[t]
}
