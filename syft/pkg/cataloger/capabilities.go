package cataloger

import (
	"embed"

	"github.com/anchore/syft/internal/capabilities"
)

//go:embed */capabilities.yaml
var catalogerFiles embed.FS

func init() {
	capabilities.RegisterCatalogerFiles(catalogerFiles)
}
