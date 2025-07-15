package licenses

import (
	"context"
	"io"
)

func (s *scanner) FindEvidence(_ context.Context, reader io.Reader) (evidence []Evidence, content []byte, err error) {
	if s.scanner == nil {
		return nil, nil, nil
	}

	content, err = io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	cov := s.scanner(content)
	if cov.Percent < s.coverageThreshold {
		// unknown or no licenses here
		// => check return content to Search to process
		return nil, content, nil
	}

	evidence = make([]Evidence, 0)
	for _, m := range cov.Match {
		evidence = append(evidence, Evidence{
			ID:    m.ID,
			Type:  m.Type,
			Start: m.Start,
			End:   m.End,
			IsURL: m.IsURL,
		})
	}
	return evidence, content, nil
}
