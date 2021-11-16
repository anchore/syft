package cmd

import (
	"fmt"
	"sync"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/presenter/poweruser"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/source"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
)

const powerUserExample = `  {{.appName}} {{.command}} <image>

  Only image sources are supported (e.g. docker: , docker-archive: , oci: , etc.), the directory source (dir:) is not supported.

  All behavior is controlled via application configuration and environment variables (see https://github.com/anchore/syft#configuration)
`

var powerUserOpts = struct {
	configPath string
}{}

var powerUserCmd = &cobra.Command{
	Use:   "power-user [IMAGE]",
	Short: "Run bulk operations on container images",
	Example: internal.Tprintf(powerUserExample, map[string]interface{}{
		"appName": internal.ApplicationName,
		"command": "power-user",
	}),
	Args:          validateInputArgs,
	Hidden:        true,
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
			return fmt.Errorf("cannot profile CPU and memory simultaneously")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU {
			defer profile.Start(profile.CPUProfile).Stop()
		} else if appConfig.Dev.ProfileMem {
			defer profile.Start(profile.MemProfile).Stop()
		}

		return powerUserExec(cmd, args)
	},
	ValidArgsFunction: dockerImageValidArgsFunction,
}

func init() {
	powerUserCmd.Flags().StringVarP(&powerUserOpts.configPath, "config", "c", "", "config file path with all power-user options")

	rootCmd.AddCommand(powerUserCmd)
}

func powerUserExec(_ *cobra.Command, args []string) error {
	// could be an image or a directory, with or without a scheme
	userInput := args[0]

	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()

	if err != nil {
		return err
	}

	return eventLoop(
		powerUserExecWorker(userInput),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}
func powerUserExecWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		tasks, err := powerUserTasks()
		if err != nil {
			errs <- err
			return
		}

		checkForApplicationUpdate()

		src, cleanup, err := source.New(userInput, appConfig.Registry.ToOptions())
		if err != nil {
			errs <- err
			return
		}
		defer cleanup()

		s := sbom.SBOM{
			Source: src.Metadata,
		}

		var results []<-chan artifact.Relationship
		for _, task := range tasks {
			c := make(chan artifact.Relationship)
			results = append(results, c)

			go runTask(task, &s.Artifacts, src, c, errs)
		}

		for relationship := range mergeResults(results...) {
			s.Relationships = append(s.Relationships, relationship)
		}

		bus.Publish(partybus.Event{
			Type:  event.PresenterReady,
			Value: poweruser.NewJSONPresenter(s, *appConfig),
		})
	}()
	return errs
}

func runTask(t powerUserTask, a *sbom.Artifacts, src *source.Source, c chan<- artifact.Relationship, errs chan<- error) {
	defer close(c)

	relationships, err := t(a, src)
	if err != nil {
		errs <- err
		return
	}

	for _, relationship := range relationships {
		c <- relationship
	}
}

func mergeResults(cs ...<-chan artifact.Relationship) <-chan artifact.Relationship {
	var wg sync.WaitGroup
	var results = make(chan artifact.Relationship)

	wg.Add(len(cs))
	for _, c := range cs {
		go func(c <-chan artifact.Relationship) {
			for n := range c {
				results <- n
			}
			wg.Done()
		}(c)
	}

	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}
