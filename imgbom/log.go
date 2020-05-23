package imgbom

import (
	"github.com/anchore/imgbom/imgbom/logger"
	"github.com/anchore/imgbom/internal/log"
)

func SetLogger(logger logger.Logger) {
	log.Log = logger
}
