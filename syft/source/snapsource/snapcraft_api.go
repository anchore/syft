package snapsource

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/anchore/syft/internal/log"
)

const (
	defaultChannel      = "stable"
	defaultArchitecture = "amd64"
	defaultSeries       = "16"
)

// snapcraftClient handles interactions with the Snapcraft API
type snapcraftClient struct {
	InfoAPIURL string
	FindAPIURL string
	HTTPClient *http.Client
}

// newSnapcraftClient creates a new Snapcraft API client with default settings
func newSnapcraftClient() *snapcraftClient {
	return &snapcraftClient{
		InfoAPIURL: "https://api.snapcraft.io/v2/snaps/info/",
		FindAPIURL: "https://api.snapcraft.io/v2/snaps/find",
		HTTPClient: &http.Client{},
	}
}

// snapcraftInfo represents the response from the snapcraft info API
type snapcraftInfo struct {
	ChannelMap []snapChannelMapEntry `json:"channel-map"`
}

type snapChannelMapEntry struct {
	Channel  snapChannel  `json:"channel"`
	Download snapDownload `json:"download"`
}
type snapChannel struct {
	Architecture string `json:"architecture"`
	Name         string `json:"name"`
}

type snapDownload struct {
	URL string `json:"url"`
}

// snapFindResponse represents the response from the snapcraft find API (search v2)
type snapFindResponse struct {
	Results []struct {
		Name   string   `json:"name"`
		SnapID string   `json:"snap-id"`
		Snap   struct{} `json:"snap"`
	} `json:"results"`
}

// GetSnapDownloadURL retrieves the download URL for a snap package
func (c *snapcraftClient) GetSnapDownloadURL(id snapIdentity) (string, error) {
	apiURL := c.InfoAPIURL + id.Name

	log.WithFields("name", id.Name, "channel", id.Channel, "architecture", id.Architecture).Trace("requesting snap info")

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Snap-Device-Series", defaultSeries)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// handle 404 case - check if snap exists via find API
	if resp.StatusCode == http.StatusNotFound {
		log.WithFields("name", id.Name).Debug("snap info not found, checking if snap exists via find API")

		exists, snapID, findErr := c.CheckSnapExists(id.Name)
		if findErr != nil {
			return "", fmt.Errorf("failed to check if snap exists: %w", findErr)
		}

		if exists {
			return "", fmt.Errorf("found snap '%s' (id=%s) but it is unavailable for download", id.Name, snapID)
		}
		return "", fmt.Errorf("no snap found with name '%s'", id.Name)
	}

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

// CheckSnapExists uses the find API (search v2) to check if a snap exists
func (c *snapcraftClient) CheckSnapExists(snapName string) (bool, string, error) {
	req, err := http.NewRequest(http.MethodGet, c.FindAPIURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to create find request: %w", err)
	}

	q := req.URL.Query()
	q.Add("name-startswith", snapName)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Snap-Device-Series", defaultSeries)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("failed to send find request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("find API request failed with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("failed to read find response body: %w", err)
	}

	var findResp snapFindResponse
	if err := json.Unmarshal(body, &findResp); err != nil {
		return false, "", fmt.Errorf("failed to parse find JSON response: %w", err)
	}

	// Look for exact name match
	for _, result := range findResp.Results {
		if result.Name == snapName {
			return true, result.SnapID, nil
		}
	}

	return false, "", nil
}
