package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/anchore"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/presenter"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
)

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [SOURCE]", internal.ApplicationName),
	Short: "A tool for generating a Software Bill Of Materials (PackageSBOM) from container images and filesystems",
	Long: internal.Tprintf(`
Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon
    {{.appName}} path/to/yourproject        a Docker tar, OCI tar, OCI directory, or generic filesystem directory 

You can also explicitly specify the scheme to use:
    {{.appName}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Podman or otherwise)
    {{.appName}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} dir:path/to/yourproject                read directly from a path on disk (any directory)
`, map[string]interface{}{
		"appName": internal.ApplicationName,
	}),
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			err := cmd.Help()
			if err != nil {
				log.Errorf(err.Error())
				os.Exit(1)
			}
			os.Exit(1)
		}
		err := doRunCmd(cmd, args)
		if err != nil {
			log.Errorf(err.Error())
			os.Exit(1)
		}
	},
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		// Since we use ValidArgsFunction, Cobra will call this AFTER having parsed all flags and arguments provided
		dockerImageRepoTags, err := ListLocalDockerImages(toComplete)
		if err != nil {
			// Indicates that an error occurred and completions should be ignored
			return []string{"completion failed"}, cobra.ShellCompDirectiveError
		}
		if len(dockerImageRepoTags) == 0 {
			return []string{"no docker images found"}, cobra.ShellCompDirectiveError
		}
		// ShellCompDirectiveDefault indicates that the shell will perform its default behavior after completions have
		// been provided (without implying other possible directives)
		return dockerImageRepoTags, cobra.ShellCompDirectiveDefault
	},
}

func startWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if appConfig.CheckForAppUpdate {
			isAvailable, newVersion, err := version.IsUpdateAvailable()
			if err != nil {
				log.Errorf(err.Error())
			}
			if isAvailable {
				log.Infof("new version of %s is available: %s", internal.ApplicationName, newVersion)

				bus.Publish(partybus.Event{
					Type:  event.AppUpdateAvailable,
					Value: newVersion,
				})
			} else {
				log.Debugf("no new %s update available", internal.ApplicationName)
			}
		}

		src, catalog, distro, err := syft.Catalog(userInput, appConfig.ScopeOpt)
		if err != nil {
			errs <- fmt.Errorf("failed to catalog input: %+v", err)
			return
		}

		if appConfig.Anchore.UploadEnabled {
			// TODO: ETUI element for this
			log.Infof("uploading results to %s", appConfig.Anchore.Hostname)

			c, err := anchore.NewClient(anchore.Configuration{
				Hostname: appConfig.Anchore.Hostname,
				Username: appConfig.Anchore.Username,
				Password: appConfig.Anchore.Password,
			})
			if err != nil {
				errs <- fmt.Errorf("failed to create anchore client: %+v", err)
				return
			}

			_, _, err = c.Import(context.Background(), catalog) //add dockerfile contents...
			if err != nil {
				errs <- fmt.Errorf("failed to upload results to host=%s: %+v", appConfig.Anchore.Hostname, err)
				return
			}

			// TODO: show status / session ID?
		}

		bus.Publish(partybus.Event{
			Type:  event.CatalogerFinished,
			Value: presenter.GetPresenter(appConfig.PresenterOpt, src.Metadata, catalog, distro),
		})
	}()
	return errs
}

func doRunCmd(_ *cobra.Command, args []string) error {
	userInput := args[0]
	errs := startWorker(userInput)
	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	return ux(errs, eventSubscription)
}

func ListLocalDockerImages(prefix string) ([]string, error) {
	var repoTags = make([]string, 0)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return repoTags, err
	}

	// Only want to return tagged images
	imageListArgs := filters.NewArgs()
	imageListArgs.Add("dangling", "false")
	images, err := cli.ImageList(ctx, types.ImageListOptions{All: false, Filters: imageListArgs})
	if err != nil {
		return repoTags, err
	}

	for _, image := range images {
		// image may have multiple tags
		for _, tag := range image.RepoTags {
			if strings.HasPrefix(tag, prefix) {
				repoTags = append(repoTags, tag)
			}
		}
	}
	return repoTags, nil
}
