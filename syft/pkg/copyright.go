package pkg

import (
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"
)

type Copyright struct {
	URL       string `json:"url,omitempty"`
	Author    string `json:"author"`
	StartYear string `json:"startYear"`
	EndYear   string `json:"endYear"`
}

type Copyrights []Copyright

func (c Copyrights) Len() int {
	return len(c)
}

func (c Copyrights) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c Copyrights) Less(i, j int) bool {
	return c[i].Author < c[j].Author
}

// Merge attempts to merge two Copyright instances. It merges URLs if the Author,
// StartYear, and EndYear are the same or compatible.
func (s Copyright) Merge(c Copyright) (*Copyright, error) {
	// Check if the Author is the same
	if s.Author != c.Author {
		return nil, fmt.Errorf("cannot merge copyrights with different authors: %s vs %s", s.Author, c.Author)
	}

	// Check if the StartYear and EndYear are compatible
	if s.StartYear != c.StartYear || s.EndYear != c.EndYear {
		return nil, fmt.Errorf("cannot merge copyrights with different years: %s-%s vs %s-%s", s.StartYear, s.EndYear, c.StartYear, c.EndYear)
	}

	// Merge URLs
	if c.URL != "" {
		s.URL = mergeURLs(s.URL, c.URL)
	}

	return &s, nil
}

// mergeURLs merges two URL strings, deduplicates, and sorts them.
func mergeURLs(sURL, cURL string) string {
	var urls []string
	if sURL != "" {
		urls = append(urls, sURL)
	}
	if cURL != "" {
		urls = append(urls, cURL)
	}

	if len(urls) > 0 {
		// Deduplicate and sort URLs
		urlsSet := strset.New(urls...)
		sortedURLs := urlsSet.List()
		sort.Strings(sortedURLs)
		return sortedURLs[0] // Assuming we return the first one or join them into a single string
	}
	return ""
}
