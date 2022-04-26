package eventloop

import (
	"os"
	"os/signal"
	"syscall"
)

func SetupSignals() <-chan os.Signal {
	c := make(chan os.Signal, 1) // Note: A buffered channel is recommended for this; see https://golang.org/pkg/os/signal/#Notify

	interruptions := []os.Signal{
		syscall.SIGINT,
		syscall.SIGTERM,
	}

	signal.Notify(c, interruptions...)

	return c
}
