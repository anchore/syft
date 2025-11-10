package model

import (
	"encoding/json"
)

// IDLikes represents a list of distribution IDs that this Linux distribution is similar to or derived from, as defined in os-release ID_LIKE field.
type IDLikes []string

// LinuxRelease contains Linux distribution identification and version information extracted from /etc/os-release or similar system files.
type LinuxRelease struct {
	// PrettyName is a human-readable operating system name with version.
	PrettyName string `json:"prettyName,omitempty"`

	// Name is the operating system name without version information.
	Name string `json:"name,omitempty"`

	// ID is the lower-case operating system identifier (e.g., "ubuntu", "rhel").
	ID string `json:"id,omitempty"`

	// IDLike is a list of operating system IDs this distribution is similar to or derived from.
	IDLike IDLikes `json:"idLike,omitempty"`

	// Version is the operating system version including codename if available.
	Version string `json:"version,omitempty"`

	// VersionID is the operating system version number or identifier.
	VersionID string `json:"versionID,omitempty"`

	// VersionCodename is the operating system release codename (e.g., "jammy", "bullseye").
	VersionCodename string `json:"versionCodename,omitempty"`

	// BuildID is a build identifier for the operating system.
	BuildID string `json:"buildID,omitempty"`

	// ImageID is an identifier for container or cloud images.
	ImageID string `json:"imageID,omitempty"`

	// ImageVersion is the version for container or cloud images.
	ImageVersion string `json:"imageVersion,omitempty"`

	// Variant is the operating system variant name (e.g., "Server", "Workstation").
	Variant string `json:"variant,omitempty"`

	// VariantID is the lower-case operating system variant identifier.
	VariantID string `json:"variantID,omitempty"`

	// HomeURL is the homepage URL for the operating system.
	HomeURL string `json:"homeURL,omitempty"`

	// SupportURL is the support or help URL for the operating system.
	SupportURL string `json:"supportURL,omitempty"`

	// BugReportURL is the bug reporting URL for the operating system.
	BugReportURL string `json:"bugReportURL,omitempty"`

	// PrivacyPolicyURL is the privacy policy URL for the operating system.
	PrivacyPolicyURL string `json:"privacyPolicyURL,omitempty"`

	// CPEName is the Common Platform Enumeration name for the operating system.
	CPEName string `json:"cpeName,omitempty"`

	// SupportEnd is the end of support date or version identifier.
	SupportEnd string `json:"supportEnd,omitempty"`

	// ExtendedSupport indicates whether extended security or support is available.
	ExtendedSupport bool `json:"extendedSupport,omitempty"`
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
