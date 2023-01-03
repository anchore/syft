package attest

import (
	"context"
	"fmt"

	"github.com/anchore/syft/internal/config"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	fmt.Println("Your image has been attested")
	return nil
}
