package cpe

import (
	"net/url"
	"strings"
)

// candidateProductForGo attempts to find a single product name in a best-effort attempt. This implementation prefers
// to return no vendor over returning potentially nonsensical results.
func candidateProductForGo(name string) string {
	// note: url.Parse requires a scheme for correct processing, which a golang module will not have, so one is provided.
	u, err := url.Parse("http://" + name)
	if err != nil {
		return ""
	}

	cleanPath := strings.Trim(u.Path, "/")
	pathElements := strings.Split(cleanPath, "/")

	switch u.Host {
	case "golang.org", "gopkg.in":
		return cleanPath
	case "google.golang.org":
		return pathElements[0]
	}

	if len(pathElements) < 2 {
		return ""
	}

	// returning the rest of the path here means longer CPEs, it helps avoiding false-positives
	// ref: https://github.com/anchore/grype/issues/676
	return strings.Join(pathElements[1:], "/")
}

// candidateVendorForGo attempts to find a single vendor name in a best-effort attempt. This implementation prefers
// to return no vendor over returning potentially nonsensical results.
func candidateVendorForGo(name string) string {
	// note: url.Parse requires a scheme for correct processing, which a golang module will not have, so one is provided.
	u, err := url.Parse("http://" + name)
	if err != nil {
		return ""
	}

	cleanPath := strings.Trim(u.Path, "/")

	switch u.Host {
	case "google.golang.org":
		return "google"
	case "golang.org":
		return "golang"
	case "gopkg.in":
		return ""
	}

	pathElements := strings.Split(cleanPath, "/")
	if len(pathElements) < 2 {
		return ""
	}
	return pathElements[0]
}
