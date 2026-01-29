package spdxlicense

// supplementalURLToLicense contains URL-to-SPDX-ID mappings that are not in the
// official SPDX license list but are commonly found in real-world packages.
//
// These mappings supplement the auto-generated urlToLicense map from license_list.go.
// Add new entries here when you encounter license URLs that should map to SPDX IDs
// but aren't covered by the official SPDX seeAlso URLs.
//
// Guidelines for adding entries:
// - Verify the URL actually corresponds to the SPDX license
// - Prefer adding to SPDX upstream if the URL is canonical (https://github.com/spdx/license-list-XML)
// - Use this map for common variants (http vs https, alternate paths) that SPDX won't accept
var supplementalURLToLicense = map[string]string{
	// LGPL-2.1: Common http:// variant of the old-licenses path
	// SPDX has https://www.gnu.org/licenses/old-licenses/lgpl-2.1-standalone.html
	// but many Java packages use this simpler http:// URL
	"http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html": "LGPL-2.1-only",

	// BSD-3-Clause (EDL): http:// variant of Eclipse Distribution License
	// SPDX has https://www.eclipse.org/org/documents/edl-v10.php
	// but many Java packages use http:// instead of https://
	"http://www.eclipse.org/org/documents/edl-v10.php": "BSD-3-Clause",
}
