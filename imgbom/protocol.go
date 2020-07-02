package imgbom

import "strings"

// Potentially consider moving this out into a generic package that parses user input.
// Aside from scope, this is the 2nd package that looks at a string to parse the input
// and return an Option type.

const (
	UnknownProtocol ProtocolType = iota
	ImageProtocol
	DirProtocol
)

var optionStr = []string{
	"UnknownProtocol",
	"image",
	"dir",
}

type ProtocolType int

type Protocol struct {
	Type  ProtocolType
	Value string
}

func NewProtocol(userStr string) Protocol {
	candidates := strings.Split(userStr, "://")

	switch len(candidates) {
	case 2:
		if strings.HasPrefix(userStr, "dir://") {
			return Protocol{
				Type:  DirProtocol,
				Value: strings.TrimPrefix(userStr, "dir://"),
			}
		}
		// default to an Image for anything else since stereoscope can handle this
		return Protocol{
			Type:  ImageProtocol,
			Value: userStr,
		}
	default:
		return Protocol{
			Type:  ImageProtocol,
			Value: userStr,
		}
	}
}

func (o ProtocolType) String() string {
	if int(o) >= len(optionStr) || o < 0 {
		return optionStr[0]
	}

	return optionStr[o]
}
