package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/spdxlicense"
)

func TestSPDXLicenseListIsTheLatest(t *testing.T) {
	resp, err := http.Get("https://spdx.org/licenses/licenses.json")
	if err != nil {
		t.Fatalf("unable to get licenses list: %+v", err)
	}

	type licenseList struct {
		Version  string `json:"licenseListVersion"`
		Licenses []struct {
			ID          string   `json:"licenseId"`
			Name        string   `json:"name"`
			Text        string   `json:"licenseText"`
			Deprecated  bool     `json:"isDeprecatedLicenseId"`
			OSIApproved bool     `json:"isOsiApproved"`
			SeeAlso     []string `json:"seeAlso"`
		} `json:"licenses"`
	}

	var latest licenseList
	if err = json.NewDecoder(resp.Body).Decode(&latest); err != nil {
		t.Fatalf("unable to decode license list: %+v", err)
	}

	assert.Equal(t, latest.Version, spdxlicense.Version)
}
