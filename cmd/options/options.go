package options

import "github.com/spf13/cobra"

// Indent is the standard indent used by all syft commands
const Indent = "  "

type Interface interface {
	// AddFlags adds this options flags to the cobra command.
	// It can also optionally bind select options to the config
	AddFlags(cmd *cobra.Command)
}

// TODO: Comment explaining relation between flags and config
