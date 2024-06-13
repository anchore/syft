package pkg

import "github.com/anchore/syft/syft/sort"

type RDescription struct {
	/*
		Fields chosen by:
			docker run --rm -it rocker/r-ver bash
			$ install2.r ggplot2 # has a lot of dependencies
			$ find /usr/local/lib/R -name DESCRIPTION | xargs cat | grep -v '^\s' | cut -d ':' -f 1 | sort | uniq -c | sort -nr

		For more information on the DESCRIPTION file see https://r-pkgs.org/description.html
	*/
	Title            string   `json:"title,omitempty"`
	Description      string   `json:"description,omitempty"`
	Author           string   `json:"author,omitempty"`
	Maintainer       string   `json:"maintainer,omitempty"`
	URL              []string `json:"url,omitempty"`
	Repository       string   `json:"repository,omitempty"`
	Built            string   `json:"built,omitempty"`
	NeedsCompilation bool     `json:"needsCompilation,omitempty"`
	Imports          []string `json:"imports,omitempty"`
	Depends          []string `json:"depends,omitempty"`
	Suggests         []string `json:"suggests,omitempty"`
}

func (m RDescription) Compare(other RDescription) int {
	if i := sort.CompareOrd(m.Title, other.Title); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Description, other.Description); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Author, other.Author); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Maintainer, other.Maintainer); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.URL, other.URL); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Repository, other.Repository); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Built, other.Built); i != 0 {
		return i
	}
	if i := sort.CompareBool(m.NeedsCompilation, other.NeedsCompilation); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Imports, other.Imports); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Depends, other.Depends); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Suggests, other.Suggests); i != 0 {
		return i
	}
	return 0
}

func (m RDescription) TryCompare(other any) (bool, int) {
	if other, exists := other.(RDescription); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
