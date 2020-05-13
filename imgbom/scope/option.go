package scope

const (
	UnknownScope Option = iota
	SquashedScope
	AllLayersScope
)

type Option int

var optionStr = []string{
	"UnknownScope",
	"Squashed",
	"AllLayers",
}

func (o Option) String() string {
	if int(o) >= len(optionStr) || int(o) < 0 {
		return optionStr[0]
	}

	return optionStr[o]
}
