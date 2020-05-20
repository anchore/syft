package presenter

const (
	UnknownPresenterOption Option = iota
	JSONOption
)

var optionStr = []string{
	"UnknownPresenterOption",
	"json",
}

var Options = []Option{
	JSONOption,
}

type Option int

func (o Option) String() string {
	if int(o) >= len(optionStr) || int(o) < 0 {
		return optionStr[0]
	}

	return optionStr[o]
}