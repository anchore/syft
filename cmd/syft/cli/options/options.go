package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Interface interface {
	// AddFlags adds this options' flags to the cobra command.
	AddFlags(cmd *cobra.Command, v *viper.Viper) error
}
