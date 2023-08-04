package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

const indent = "  "

func validateArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		// in the case that no arguments are given we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

//
// func logApplicationConfig(app *config.Application) {
//	versionInfo := version2.FromBuild()
//	log.Infof("%s version: %+v", internal.ApplicationName, versionInfo.Version)
//	log.Debugf("application config:\n%+v", color.Magenta.Sprint(app.String()))
//}
//
// func newLogWrapper(app *config.Application) {
//	cfg := logrus.Config{
//		EnableConsole: (app.Log.FileLocation == "" || app.Verbosity > 0) && !app.Quiet,
//		FileLocation:  app.Log.FileLocation,
//		Level:         app.Log.Level,
//	}
//
//	if app.Log.Structured {
//		cfg.Formatter = &logrusUpstream.JSONFormatter{
//			TimestampFormat:   "2006-01-02 15:04:05",
//			DisableTimestamp:  false,
//			DisableHTMLEscape: false,
//			PrettyPrint:       false,
//		}
//	}
//
//	logWrapper, err := logrus.New(cfg)
//	if err != nil {
//		// this is kinda circular, but we can't return an error... ¯\_(ツ)_/¯
//		// I'm going to leave this here in case we one day have a different default logger other than the "discard" logger
//		log.Error("unable to initialize logger: %+v", err)
//		return
//	}
//	syft.SetLogger(logWrapper)
//	stereoscope.SetLogger(logWrapper.Nested("from-lib", "stereoscope"))
//}
