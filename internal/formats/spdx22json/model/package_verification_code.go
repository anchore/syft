package model

// Why are there two package identifier fields Package Checksum and Package Verification?
// Although the values of the two fields Package Checksum and Package Verification are similar, they each serve a
// different purpose. The Package Checksum provides a unique identifier of a software package which is computed by
// taking the SHA1 of the entire software package file. This enables one to quickly determine if two different copies
// of a package are the same. One disadvantage of this approach is that one cannot add an SPDX data file into the
// original package without changing the Package Checksum value. Alternatively, the Package Verification field enables
// the inclusion of an SPDX file. It enables one to quickly verify if one or more of the original package files has
// changed. The Package Verification field is a unique identifier that is based on SHAing only the original package
// files (e.g., excluding the SPDX file). This allows one to add an SPDX file to the original package without changing
// this unique identifier.
// source: https://wiki.spdx.org/view/SPDX_FAQ
type PackageVerificationCode struct {
	// "A file that was excluded when calculating the package verification code. This is usually a file containing
	// SPDX data regarding the package. If a package contains more than one SPDX file all SPDX files must be excluded
	// from the package verification code. If this is not done it would be impossible to correctly calculate the
	// verification codes in both files.
	PackageVerificationCodeExcludedFiles []string `json:"packageVerificationCodeExcludedFiles"`

	// The actual package verification code as a hex encoded value.
	PackageVerificationCodeValue string `json:"packageVerificationCodeValue"`
}
