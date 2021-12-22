package cmd

import (
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"
)

func checkForApplicationUpdate() {
	if appConfig.CheckForAppUpdate {
		log.Debugf("checking if new vesion of %s is available", internal.ApplicationName)
		isAvailable, newVersion, err := version.IsUpdateAvailable()
		if err != nil {
			// this should never stop the application
			log.Errorf(err.Error())
		}
		if isAvailable {
			log.Infof("new version of %s is available: %s (current version is %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)

			bus.Publish(partybus.Event{
				Type:  event.AppUpdateAvailable,
				Value: newVersion,
			})
		} else {
			log.Debugf("no new %s update available", internal.ApplicationName)
		}
	}
}
