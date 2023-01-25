package generic

import (
	"fmt"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/syft/source"
)

type Search interface {
	ByGlob(string) SearchRequest
	ByPath(string) SearchRequest
	ByBasename(string) SearchRequirement
	ByBasenameGlob(string) SearchRequirement
	ByExtension(string) SearchRequirement
	ByMimeType(...string) SearchRequirement
}

type SearchRequirement interface {
	MustMatchGlob(string) SearchRequest
	Request() SearchRequest
}

type search struct {
	SearchRequest
}

type SearchRequest struct {
	// search basis
	glob         string
	path         string
	basename     string
	basenameGlob string
	extension    string
	mimeTypes    []string
	// requirements
	matchGlob string
}

func NewSearch() Search {
	return &search{}
}

func (s *search) ByGlob(glob string) SearchRequest {
	s.glob = glob
	return s.SearchRequest
}

func (s *search) ByPath(path string) SearchRequest {
	s.path = path
	return s.SearchRequest
}

func (s *search) ByBasename(basename string) SearchRequirement {
	s.basename = basename
	return s
}

func (s *search) ByBasenameGlob(basenameGlob string) SearchRequirement {
	s.basenameGlob = basenameGlob
	return s
}

func (s *search) ByExtension(extension string) SearchRequirement {
	s.extension = extension
	return s
}

func (s *search) ByMimeType(tys ...string) SearchRequirement {
	s.mimeTypes = tys
	return s
}

func (s *search) MustMatchGlob(glob string) SearchRequest {
	s.matchGlob = glob
	return s.SearchRequest
}

func (s *search) Request() SearchRequest {
	return s.SearchRequest
}

func (s SearchRequest) String() string {
	var res string
	switch {
	case s.basename != "":
		res += fmt.Sprintf("basename=%s", s.basename)
	case s.basenameGlob != "":
		res += fmt.Sprintf("basenameGlob=%s", s.basenameGlob)
	case s.extension != "":
		res += fmt.Sprintf("extension=%s", s.extension)
	case len(s.mimeTypes) > 0:
		res += fmt.Sprintf("mimeTypes=%s", s.mimeTypes)
	case s.glob != "":
		res += fmt.Sprintf("glob=%s", s.glob)
	case s.path != "":
		res += fmt.Sprintf("path=%s", s.path)
	default:
		res = "no search criteria"
		return res
	}

	if s.matchGlob != "" {
		res += fmt.Sprintf(" and result must match glob=%s", s.matchGlob)
	}
	return res
}

func (s SearchRequest) Execute(resolver source.FileResolver) ([]source.Location, error) {
	var locations []source.Location
	var err error

	switch {
	case s.glob != "":
		locations, err = resolver.FilesByGlob(s.glob)
		if err != nil {
			return nil, fmt.Errorf("unable to process search glob=%q: %w", s.glob, err)
		}
	case s.path != "":
		locations, err = resolver.FilesByPath(s.path)
		if err != nil {
			return nil, fmt.Errorf("unable to process search path=%q: %w", s.path, err)
		}
	case s.basename != "":
		locations, err = resolver.FilesByBasename(s.basename)
		if err != nil {
			return nil, fmt.Errorf("unable to process search basis basename=%q: %w", s.basename, err)
		}
	case s.basenameGlob != "":
		locations, err = resolver.FilesByBasenameGlob(s.basenameGlob)
		if err != nil {
			return nil, fmt.Errorf("unable to process search basis basename=%q: %w", s.basename, err)
		}
	case s.extension != "":
		locations, err = resolver.FilesByExtension(s.extension)
		if err != nil {
			return nil, fmt.Errorf("unable to process search basis extension=%q: %w", s.extension, err)
		}
	case len(s.mimeTypes) > 0:
		for _, t := range s.mimeTypes {
			locations, err = resolver.FilesByMIMEType(t)
			if err != nil {
				return nil, fmt.Errorf("unable to process search basis mimetype=%q: %w", t, err)
			}
		}
	}

	if s.matchGlob != "" {
		// overwrite the locations with the filtered set
		locations, err = s.matchRequirementGlob(locations)
		if err != nil {
			return nil, err
		}
	}

	return locations, nil
}

func (s SearchRequest) matchRequirementGlob(locations []source.Location) ([]source.Location, error) {
	var globMatches []source.Location
	var err error
forMatches:
	for _, m := range locations {
		var matchesGlob bool
		for _, path := range []string{m.RealPath, m.VirtualPath} {
			matchesGlob, err = doublestar.Match(s.matchGlob, path)
			if err != nil {
				return nil, fmt.Errorf("unable to validate glob requirement=%q: %w", s.matchGlob, err)
			}
			if matchesGlob {
				globMatches = append(globMatches, m)
				continue forMatches
			}
		}
	}
	return globMatches, nil
}
