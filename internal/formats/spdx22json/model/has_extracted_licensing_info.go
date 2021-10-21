package model

type HasExtractedLicensingInfo struct {
	// Verbatim license or licensing notice text that was discovered.
	ExtractedText string `json:"extractedText"`
	// A human readable short form license identifier for a license. The license ID is iether on the standard license
	// oist or the form \"LicenseRef-\"[idString] where [idString] is a unique string containing letters,
	// numbers, \".\", \"-\" or \"+\".
	LicenseID string `json:"licenseId"`
	Comment   string `json:"comment,omitempty"`
	// Identify name of this SpdxElement.
	Name     string   `json:"name,omitempty"`
	SeeAlsos []string `json:"seeAlsos,omitempty"`
}
