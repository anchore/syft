package commands

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/ui"
)

func disableUI(app clio.Application, out io.Writer) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, _ []string) error {
		type Stater interface {
			State() *clio.State
		}

		state := app.(Stater).State()
		state.UI = clio.NewUICollection(ui.None(out, state.Config.Log.Quiet))

		return nil
	}
}
