package model

import "time"

type CreationInfo struct {
	Comment string `json:"comment,omitempty"`
	// Identify when the SPDX file was originally created. The date is to be specified according to combined date and
	// time in UTC format as specified in ISO 8601 standard. This field is distinct from the fields in section 8,
	// which involves the addition of information during a subsequent review.
	Created time.Time `json:"created"`
	// Identify who (or what, in the case of a tool) created the SPDX file. If the SPDX file was created by an
	// individual, indicate the person's name. If the SPDX file was created on behalf of a company or organization,
	// indicate the entity name. If the SPDX file was created using a software tool, indicate the name and version
	// for that tool. If multiple participants or tools were involved, use multiple instances of this field. Person
	// name or organization name may be designated as “anonymous” if appropriate.
	Creators []string `json:"creators"`
	// An optional field for creators of the SPDX file to provide the version of the SPDX License List used when the SPDX file was created.
	LicenseListVersion string `json:"licenseListVersion"`
}
