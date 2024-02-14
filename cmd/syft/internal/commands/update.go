package commands

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	hashiVersion "github.com/anchore/go-version"
	"github.com/anchore/syft/cmd/syft/internal"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/parsers"
)

var latestAppVersionURL = struct {
	host string
	path string
}{
	host: "https://toolbox-data.anchore.io",
	path: "/syft/releases/latest/VERSION",
}

func applicationUpdateCheck(id clio.Identification, check *options.UpdateCheck) func(cmd *cobra.Command, args []string) error {
	return func(_ *cobra.Command, _ []string) error {
		if check.CheckForAppUpdate {
			checkForApplicationUpdate(id)
		}
		return nil
	}
}

func checkForApplicationUpdate(id clio.Identification) {
	log.Debugf("checking if a new version of %s is available", id.Name)
	isAvailable, newVersion, err := isUpdateAvailable(id)
	if err != nil {
		// this should never stop the application
		log.Errorf(err.Error())
	}
	if isAvailable {
		log.Infof("new version of %s is available: %s (current version is %s)", id.Name, newVersion, id.Version)

		bus.Publish(partybus.Event{
			Type: event.CLIAppUpdateAvailable,
			Value: parsers.UpdateCheck{
				New:     newVersion,
				Current: id.Version,
			},
		})
	} else {
		log.Debugf("no new %s update available", id.Name)
	}
}

// isUpdateAvailable indicates if there is a newer application version available, and if so, what the new version is.
func isUpdateAvailable(id clio.Identification) (bool, string, error) {
	if !isProductionBuild(id.Version) {
		// don't allow for non-production builds to check for a version.
		return false, "", nil
	}

	currentVersion, err := hashiVersion.NewVersion(id.Version)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse current application version: %w", err)
	}

	latestVersion, err := fetchLatestApplicationVersion(id)
	if err != nil {
		return false, "", err
	}

	if latestVersion.GreaterThan(currentVersion) {
		return true, latestVersion.String(), nil
	}

	return false, "", nil
}

func isProductionBuild(version string) bool {
	if strings.Contains(version, "SNAPSHOT") || strings.Contains(version, internal.NotProvided) {
		return false
	}
	return true
}

func fetchLatestApplicationVersion(id clio.Identification) (*hashiVersion.Version, error) {
	req, err := http.NewRequest(http.MethodGet, latestAppVersionURL.host+latestAppVersionURL.path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for latest version: %w", err)
	}
	req.Header.Add("User-Agent", fmt.Sprintf("%v %v", id.Name, id.Version))

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest version: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d on fetching latest version: %s", resp.StatusCode, resp.Status)
	}

	versionBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read latest version: %w", err)
	}

	versionStr := strings.TrimSuffix(string(versionBytes), "\n")
	if len(versionStr) > 50 {
		return nil, fmt.Errorf("version too long: %q", versionStr[:50])
	}

	return hashiVersion.NewVersion(versionStr)
}
