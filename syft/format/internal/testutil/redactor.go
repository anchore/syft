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
	Replace string
}

func NewPatternReplacement(r *regexp.Regexp) PatternReplacement {
	return PatternReplacement{
		Search:  r,
		Replace: "redacted",
	}
}

func (p PatternReplacement) Redact(b []byte) []byte {
	return p.Search.ReplaceAll(b, []byte(p.Replace))
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
