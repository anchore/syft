package snapsource

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

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

type SnapRisk string

const (
	RiskStable    SnapRisk = "stable"
	RiskCandidate SnapRisk = "candidate"
	RiskBeta      SnapRisk = "beta"
	RiskEdge      SnapRisk = "edge"
	RiskUnknown   SnapRisk = "unknown"
)

func isValidSnapRisk(r SnapRisk) bool {
	switch r {
	case RiskStable, RiskCandidate, RiskBeta, RiskEdge:
		return true
	default:
		return false
	}
}

func stringToSnapRisk(s string) SnapRisk {
	r := SnapRisk(s)
	if !isValidSnapRisk(r) {
		return RiskUnknown
	}
	return r
}

func getRevisionFromURL(cm snapChannelMapEntry) (rev int, err error) {
	re := regexp.MustCompile(`(\d+)\.snap$`)
	match := re.FindStringSubmatch(cm.Download.URL)
	if len(match) < 2 {
		err = fmt.Errorf("could not determine revision from %s", cm.Download.URL)
		return
	}
	rev, err = strconv.Atoi(match[1])
	return
}

// isEligibleChannel determines whether a candidate channel satisfies a requested
// channel. Both channels are parsed into {track, risk} pairs.
//
// Matching rules:
//   - If the request includes a track, both track and risk must match exactly.
//   - If the request omits the track (e.g., "stable"), any candidate track is
//     accepted as long as the risk matches.
//
// Examples:
//
//	candidate="3.2/stable", request="stable"       -> true
//	candidate="3.2/stable", request="3.2/stable"   -> true
//	candidate="3.2/stable", request="3.2/beta"     -> false
//	candidate="3.2/beta",   request="stable"       -> false
//	candidate="3.2/alpha", request="alpha"         -> false(alpha is an invalid risk level)
//	candidate="3.2/stable/fix-for-bug123", request="stable"       -> true
//	candidate="3.2/stable/fix-for-bug123", request="3.2/stable"   -> true
func isEligibleChannel(candidate, request string) (bool, error) {
	cTrack, cRisk, cBranch := splitChannel(candidate)
	rTrack, rRisk, rBranch := splitChannel(request)
	if rTrack == "" && rRisk == "" && rBranch == "" {
		return false, fmt.Errorf("there is no such risk in the channel(only stable/candidate/beta/edge are valid)")
	}

	if rTrack != "" {
		return cTrack == rTrack && cRisk == rRisk && (cBranch == rBranch || rBranch == ""), nil
	}

	return cRisk == rRisk && (cBranch == rBranch || rBranch == ""), nil
}

func splitChannel(ch string) (track string, risk string, branch string) {
	parts := strings.SplitN(ch, "/", 3)
	if stringToSnapRisk(parts[0]) != RiskUnknown {
		if len(parts) == 1 {
			return "", parts[0], "" // no track
		} else if len(parts) == 2 {
			return "", parts[0], parts[1]
		}
	} else if len(parts) >= 2 && stringToSnapRisk(parts[1]) != RiskUnknown {
		if len(parts) == 3 {
			return parts[0], parts[1], parts[2]
		} else if len(parts) == 2 {
			return parts[0], parts[1], ""
		}
	}

	return "", "", ""
}

func matchSnapDownloadURL(cm snapChannelMapEntry, id snapIdentity) (string, error) {
	// revision will supersede channel
	if id.Revision != NotSpecifiedRevision {
		rev, err2 := getRevisionFromURL(cm)
		if err2 == nil && rev == id.Revision {
			return cm.Download.URL, nil
		}
	} else if cm.Channel.Architecture == id.Architecture {
		matched, err2 := isEligibleChannel(cm.Channel.Name, id.Channel)
		if err2 != nil {
			return "", err2
		}
		if matched {
			return cm.Download.URL, nil
		}
	}
	return "", nil
}

// GetSnapDownloadURL retrieves the download URL for a snap package
func (c *snapcraftClient) GetSnapDownloadURL(id snapIdentity) (string, error) {
	apiURL := c.InfoAPIURL + id.Name

	if id.Revision == NotSpecifiedRevision {
		log.WithFields("name", id.Name, "channel", id.Channel, "architecture", id.Architecture).Trace("requesting snap info")
	} else {
		log.WithFields("name", id.Name, "revision", id.Revision, "architecture", id.Architecture).Trace("requesting snap info")
	}

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if id.Revision != NotSpecifiedRevision {
		q := req.URL.Query()
		q.Add("revision", fmt.Sprintf("%d", id.Revision))
		req.URL.RawQuery = q.Encode()
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
		url, err2 := matchSnapDownloadURL(cm, id)
		if url == "" && err2 == nil {
			continue
		}
		return url, err2
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
