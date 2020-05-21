package imgbom

import "github.com/anchore/imgbom/internal/logger"

func SetLogger(l logger.Logger) {
	logger.SetLogger(l)
}
