package testutil

import (
	"bytes"
	"regexp"
)

var (
	_ Redactor = (*RedactorFn)(nil)
	_ Redactor = (*PatternReplacement)(nil)
	_ Redactor = (*ValueReplacement)(nil)
	_ Redactor = (*Redactions)(nil)
)

type Redactor interface {
	Redact([]byte) []byte
}

// Replace by function //////////////////////////////

type RedactorFn func([]byte) []byte

func (r RedactorFn) Redact(b []byte) []byte {
	return r(b)
}

// Replace by regex //////////////////////////////

type PatternReplacement struct {
	Search  *regexp.Regexp
	Groups  []string
	Replace string
}

func NewPatternReplacement(r *regexp.Regexp) PatternReplacement {
	return PatternReplacement{
		Search:  r,
		Replace: "redacted",
	}
}

func (p PatternReplacement) Redact(b []byte) []byte {
	if len(p.Groups) == 0 {
		return p.Search.ReplaceAll(b, []byte(p.Replace))
	}

	return p.redactNamedGroups(b)
}

func (p PatternReplacement) redactNamedGroups(b []byte) []byte {
	groupsToReplace := make(map[string]bool)
	for _, g := range p.Groups {
		groupsToReplace[g] = true
	}

	subexpNames := p.Search.SubexpNames()

	return p.Search.ReplaceAllFunc(b, func(match []byte) []byte {
		indexes := p.Search.FindSubmatchIndex(match)
		if indexes == nil {
			return match
		}

		result := make([]byte, len(match))
		copy(result, match)

		// keep track of the offset as we replace groups
		offset := 0

		// process each named group
		for i, name := range subexpNames {
			// skip the full match (i==0) and groups we don't want to replace
			if i == 0 || !groupsToReplace[name] {
				continue
			}

			// get the start and end positions of this group
			startPos := indexes[2*i]
			endPos := indexes[2*i+1]

			// skip if the group didn't match
			if startPos < 0 || endPos < 0 {
				continue
			}

			// adjust positions based on previous replacements
			startPos += offset
			endPos += offset

			// replace the group with our replacement text
			beforeGroup := result[:startPos]
			afterGroup := result[endPos:]

			// calculate the new offset
			oldLen := endPos - startPos
			newLen := len(p.Replace)
			offset += (newLen - oldLen)

			result = append(beforeGroup, append([]byte(p.Replace), afterGroup...)...) //nolint:gocritic
		}

		return result
	})
}

// Replace by value //////////////////////////////

type ValueReplacement struct {
	Search  string
	Replace string
}

func NewValueReplacement(v string) ValueReplacement {
	return ValueReplacement{
		Search:  v,
		Replace: "redacted",
	}
}

func (v ValueReplacement) Redact(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte(v.Search), []byte(v.Replace))
}

// Handle a collection of redactors //////////////////////////////

type Redactions struct {
	redactors []Redactor
}

func NewRedactions(redactors ...Redactor) *Redactions {
	r := &Redactions{
		redactors: redactors,
	}

	return r.WithFunctions(carriageRedactor)
}

func (r *Redactions) WithPatternRedactors(values map[string]string) *Redactions {
	for k, v := range values {
		r.redactors = append(r.redactors,
			PatternReplacement{
				Search:  regexp.MustCompile(k),
				Replace: v,
			},
		)
	}
	return r
}

func (r *Redactions) WithPatternRedactorSpec(values ...PatternReplacement) *Redactions {
	for _, v := range values {
		r.redactors = append(r.redactors, v)
	}
	return r
}

func (r *Redactions) WithValueRedactors(values map[string]string) *Redactions {
	for k, v := range values {
		r.redactors = append(r.redactors,
			ValueReplacement{
				Search:  k,
				Replace: v,
			},
		)
	}
	return r
}

func (r *Redactions) WithPatternsRedacted(values ...string) *Redactions {
	for _, pattern := range values {
		r.redactors = append(r.redactors,
			NewPatternReplacement(regexp.MustCompile(pattern)),
		)
	}
	return r
}

func (r *Redactions) WithValuesRedacted(values ...string) *Redactions {
	for _, v := range values {
		r.redactors = append(r.redactors,
			NewValueReplacement(v),
		)
	}
	return r
}

func (r *Redactions) WithFunctions(values ...func([]byte) []byte) *Redactions {
	for _, fn := range values {
		r.redactors = append(r.redactors,
			RedactorFn(fn),
		)
	}
	return r
}

func (r *Redactions) WithRedactors(rs ...Redactor) *Redactions {
	r.redactors = append(r.redactors, rs...)
	return r
}

func (r Redactions) Redact(b []byte) []byte {
	for _, redactor := range r.redactors {
		b = redactor.Redact(b)
	}
	return b
}

func carriageRedactor(s []byte) []byte {
	return bytes.ReplaceAll(s, []byte("\r\n"), []byte("\n"))
}
