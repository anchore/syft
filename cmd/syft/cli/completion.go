package cli

import (
	"os"

	"github.com/spf13/cobra"
)

func Completion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate a shell completion for Syft (listing local docker images)",
		Long: `To load completions (docker image list):
	Bash:
	$ source <(syft completion bash)
# To load completions for each session, execute once:
	Linux:
	  $ syft completion bash > /etc/bash_completion.d/syft
	MacOS:
	  $ syft completion bash > /usr/local/etc/bash_completion.d/syft
	Zsh:
# If shell completion is not already enabled in your environment you will need
# to enable it.  You can execute the following once:
	$ echo "autoload -U compinit; compinit" >> ~/.zshrc
# To load completions for each session, execute once:
	$ syft completion zsh > "${fpath[1]}/_syft"
# You will need to start a new shell for this setup to take effect.
	Fish:
	$ syft completion fish | source
# To load completions for each session, execute once:
	$ syft completion fish > ~/.config/fish/completions/syft.fish
	`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish"},
		Args:                  cobra.ExactValidArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			switch args[0] {
			case "bash":
				err = cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				err = cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				err = cmd.Root().GenFishCompletion(os.Stdout, true)
			}
			if err != nil {
				return err
			}
			return nil
		},
	}

	return cmd
}
