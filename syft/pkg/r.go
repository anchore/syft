package pkg

// Fields chosen by:
//   docker run --rm -it rocker/r-ver bash
//   $ install2.r ggplot2 # has a lot of dependencies
//   $ find /usr/local/lib/R -name DESCRIPTION | xargs cat | grep -v '^\s' | cut -d ':' -f 1 | sort | uniq -c | sort -nr
//
// For more information on the DESCRIPTION file see https://r-pkgs.org/description.html

// RDescription represents metadata from an R package DESCRIPTION file containing package information, dependencies, and author details.
type RDescription struct {
	// Title is short one-line package title
	Title string `json:"title,omitempty"`

	// Description is detailed package description
	Description string `json:"description,omitempty"`

	// Author is package author(s)
	Author string `json:"author,omitempty"`

	// Maintainer is current package maintainer
	Maintainer string `json:"maintainer,omitempty"`

	// URL is the list of related URLs
	URL []string `json:"url,omitempty"`

	// Repository is CRAN or other repository name
	Repository string `json:"repository,omitempty"`

	// Built is R version and platform this was built with
	Built string `json:"built,omitempty"`

	// NeedsCompilation is whether this package requires compilation
	NeedsCompilation bool `json:"needsCompilation,omitempty"`

	// Imports are the packages imported in the NAMESPACE
	Imports []string `json:"imports,omitempty"`

	// Depends are the packages this package depends on
	Depends []string `json:"depends,omitempty"`

	// Suggests are the optional packages that extend functionality
	Suggests []string `json:"suggests,omitempty"`
}
