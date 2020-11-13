package pkg

type Language string

const (
	UnknownLanguage Language = "UnknownLanguage"
	Java            Language = "java"
	JavaScript      Language = "javascript"
	Python          Language = "python"
	Ruby            Language = "ruby"
	Go              Language = "go"
)

var AllLanguages = []Language{
	Java,
	JavaScript,
	Python,
	Ruby,
	Go,
}

func (l Language) String() string {
	return string(l)
}
