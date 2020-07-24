package scope

import "strings"

// Potentially consider moving this out into a generic package that parses user input.
// Aside from scope, this is the 2nd package that looks at a string to parse the input
// and return an Option type.

const (
	// nolint:varcheck,deadcode
	unknownProtocol protocolType = iota
	imageProtocol
	directoryProtocol
)

var protocolStr = []string{
	"UnknownProtocol",
	"Image",
	"Directory",
}

type protocolType int

type protocol struct {
	Type  protocolType
	Value string
}

func newProtocol(userStr string) protocol {
	candidates := strings.Split(userStr, "://")

	switch len(candidates) {
	case 2:
		if strings.HasPrefix(userStr, "dir://") {
			return protocol{
				Type:  directoryProtocol,
				Value: strings.TrimPrefix(userStr, "dir://"),
			}
		}
		// default to an Image for anything else since stereoscope can handle this
		return protocol{
			Type:  imageProtocol,
			Value: userStr,
		}
	default:
		return protocol{
			Type:  imageProtocol,
			Value: userStr,
		}
	}
}

func (o protocolType) String() string {
	if int(o) >= len(protocolStr) || o < 0 {
		return protocolStr[0]
	}

	return protocolStr[o]
}
