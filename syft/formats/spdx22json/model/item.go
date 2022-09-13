package model

type Item struct {
	Element
	// The licenseComments property allows the preparer of the SPDX document to describe why the licensing in
	// spdx:licenseConcluded was chosen.
	LicenseComments  string `json:"licenseComments,omitempty"`
	LicenseConcluded string `json:"licenseConcluded"`
	// The licensing information that was discovered directly within the package. There will be an instance of this
	// property for each distinct value of alllicenseInfoInFile properties of all files contained in the package.
	LicenseInfoFromFiles []string `json:"licenseInfoFromFiles,omitempty"`
	// Licensing information that was discovered directly in the subject file. This is also considered a declared license for the file.
	LicenseInfoInFiles []string `json:"licenseInfoInFiles,omitempty"`
	// The text of copyright declarations recited in the Package or File.
	CopyrightText string `json:"copyrightText,omitempty"`
	// This field provides a place for the SPDX data creator to record acknowledgements that may be required to be
	// communicated in some contexts. This is not meant to include the actual complete license text (see
	// licenseConculded and licenseDeclared), and may or may not include copyright notices (see also copyrightText).
	// The SPDX data creator may use this field to record other acknowledgements, such as particular clauses from
	// license texts, which may be necessary or desirable to reproduce.
	AttributionTexts []string `json:"attributionTexts,omitempty"`
}
