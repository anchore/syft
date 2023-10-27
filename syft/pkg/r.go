package pkg

type RDescription struct {
	/*
		Fields chosen by:
		docker run --rm -it rocker/r-ver bash
		$ install2.r ggplot2 # has a lot of dependencies
		$ find /usr/local/lib/R -name DESCRIPTION | xargs cat | grep -v '^\s' | cut -d ':' -f 1 | sort | uniq -c | sort -nr
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
