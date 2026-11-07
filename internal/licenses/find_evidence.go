package licenses

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
)

func (s *scanner) FindEvidence(_ context.Context, reader io.Reader) (evidence []Evidence, content []byte, err error) {
	if s.scanner == nil {
		return nil, nil, nil
	}

	content, err = io.ReadAll(reader) //nolint:gocritic // license scanner requires full content
	if err != nil {
		return nil, nil, err
	}

	cov := s.scanner(content)
	evidence = make([]Evidence, 0)
	for _, m := range cov.Match {
		if cov.Percent < s.coverageThreshold {
			// Retain the full text for review instead of asserting a standard license.
			hash := sha256.Sum256(content)
			m.ID = fmt.Sprintf("LicenseRef-Possible-%s-%x", m.ID, hash[:6])
			m.Start, m.End = 0, len(content)
		}
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
