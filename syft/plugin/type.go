package plugin

import (
	"fmt"

	"github.com/hashicorp/go-plugin"
)

var AllTypes = []Type{
	TypeCataloger,
}

type Type uint64

const (
	TypeUnknown Type = iota
	TypeCataloger
)

func (p Type) String() string {
	switch p {
	case TypeCataloger:
		return "cataloger"
	default:
		return "unknown"
	}
}

func (p Type) HandshakeConfig() plugin.HandshakeConfig {
	switch p {
	case TypeCataloger:
		return plugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "SYFT_CATALOGER_PLUGIN",
			MagicCookieValue: "0f86cc7f-6f97-410e-a844-087cd12e36e3",
		}
	default:
		panic(fmt.Errorf("plugin type unsupported"))
	}
}

func ParseType(pluginType string) Type {
	switch pluginType {
	case "cataloger":
		return TypeCataloger
	default:
		return TypeUnknown
	}
}
