package options

import (
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/syft/internal/log"
)

type Network struct {
	Enable []string `yaml:"enable" json:"enable" mapstructure:"enable"`
}

func (n *Network) PostLoad() error {
	n.Enable = flatten(n.Enable)
	return nil
}

func (n *Network) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&n.Enable, "network", "",
		"enable features to use the network to fetch and augment package information")
}

func (n *Network) Enabled(features ...string) *bool {
	if n == nil {
		return nil
	}
	return networkEnabled(n.Enable, features...)
}

var _ interface {
	fangs.PostLoader
	fangs.FlagAdder
} = (*Network)(nil)

func networkEnabled(networkDirectives []string, features ...string) *bool {
	if len(networkDirectives) == 0 {
		return nil
	}

	enabled := func(features ...string) *bool {
		for _, directive := range networkDirectives {
			enable := true
			directive = strings.TrimPrefix(directive, "+") // +java and java are equivalent
			if strings.HasPrefix(directive, "-") {
				directive = directive[1:]
				enable = false
			}
			for _, feature := range features {
				if directive == feature {
					return &enable
				}
			}
		}
		return nil
	}

	enableAll := enabled("all", "yes", "on", "enable", "enabled")
	disableAll := enabled("none", "no", "off", "disable", "disabled")

	if disableAll != nil {
		if enableAll != nil {
			log.Warn("you have specified to both enable and disable all network functionality, defaulting to disabled")
		} else {
			enableAll = ptr(!*disableAll)
		}
	}

	// check for explicit enable/disable of each particular feature, in order
	for _, feat := range features {
		enableFeature := enabled(feat)
		if enableFeature != nil {
			return enableFeature
		}
	}

	return enableAll
}

func ptr[T any](val T) *T {
	return &val
}
