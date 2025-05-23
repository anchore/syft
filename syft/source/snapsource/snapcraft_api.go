package snapsource

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	snapAPIURL = "https://api.snapcraft.io/v2/snaps/info/"

	defaultChannel      = "stable"
	defaultArchitecture = "amd64"
	defaultSeries       = "16"
)

// snapcraftInfo represents the response from the Snap API
type snapcraftInfo struct {
	ChannelMap []struct {
		Channel struct {
			Architecture string `json:"architecture"`
			Name         string `json:"name"`
		} `json:"channel"`
		Download struct {
			URL string `json:"url"`
		} `json:"download"`
	} `json:"channel-map"`
}

// parseSnapRequest parses a snap request into name and channel
// Examples:
// - "etcd" -> name="etcd", channel="stable" (default)
// - "etcd@beta" -> name="etcd", channel="beta"
// - "etcd@2.3/stable" -> name="etcd", channel="2.3/stable"
func parseSnapRequest(request string) (name, channel string) {
	parts := strings.SplitN(request, "@", 2)
	name = parts[0]

	if len(parts) == 2 {
		channel = parts[1]
	}

	if channel == "" {
		channel = defaultChannel
	}

	return name, channel
}

// getSnapDownloadURL retrieves the download URL for a snap package
func getSnapDownloadURL(apiBaseURL string, id snapIdentity) (string, error) {
	apiURL := apiBaseURL + id.Name

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Snap-Device-Series", defaultSeries)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var info snapcraftInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	for _, cm := range info.ChannelMap {
		if cm.Channel.Architecture == id.Architecture && cm.Channel.Name == id.Channel {
			return cm.Download.URL, nil
		}
	}

	return "", fmt.Errorf("no matching snap found for %s", id.String())
}
