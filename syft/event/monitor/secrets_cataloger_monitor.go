package monitor

import (
	"github.com/wagoodman/go-progress"
)

type SecretsCatalogerMonitor struct {
	progress.Stager
	SecretsDiscovered progress.Monitorable
	progress.Progressable
}
