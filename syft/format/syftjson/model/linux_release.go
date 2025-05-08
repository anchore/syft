package model

import (
	"encoding/json"
)

type IDLikes []string

type LinuxRelease struct {
	PrettyName       string  `json:"prettyName,omitempty"`
	Name             string  `json:"name,omitempty"`
	ID               string  `json:"id,omitempty"`
	IDLike           IDLikes `json:"idLike,omitempty"`
	Version          string  `json:"version,omitempty"`
	VersionID        string  `json:"versionID,omitempty"`
	VersionCodename  string  `json:"versionCodename,omitempty"`
	BuildID          string  `json:"buildID,omitempty"`
	ImageID          string  `json:"imageID,omitempty"`
	ImageVersion     string  `json:"imageVersion,omitempty"`
	Variant          string  `json:"variant,omitempty"`
	VariantID        string  `json:"variantID,omitempty"`
	HomeURL          string  `json:"homeURL,omitempty"`
	SupportURL       string  `json:"supportURL,omitempty"`
	BugReportURL     string  `json:"bugReportURL,omitempty"`
	PrivacyPolicyURL string  `json:"privacyPolicyURL,omitempty"`
	CPEName          string  `json:"cpeName,omitempty"`
	SupportEnd       string  `json:"supportEnd,omitempty"`
}

func (s *IDLikes) UnmarshalJSON(data []byte) error {
	var str string
	var strSlice []string

	// we support unmarshalling from a single value to support syft json schema v2
	if err := json.Unmarshal(data, &str); err == nil {
		*s = []string{str}
	} else if err := json.Unmarshal(data, &strSlice); err == nil {
		*s = strSlice
	} else {
		return err
	}
	return nil
}
