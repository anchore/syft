package ocaml

import (
	"errors"
	"fmt"
	"strings"
)

// opamFields holds the fields of an opam file (https://opam.ocaml.org/doc/Manual.html#Common-file-format)
// that are relevant for cataloging.
type opamFields struct {
	Name      string
	Version   string
	Licenses  []string
	Homepage  string
	URL       string
	Checksums []string
	Depends   []opamDependency
}

// opamDependency is a package named in a `depends` formula. Version is only set when the dependency is pinned to an
// exact version (e.g. `"lwt" {= "5.4.2"}`), as in opam lock files.
type opamDependency struct {
	Name    string
	Version string
}

// parseOpamFields parses the opam file format. Only the subset of the grammar needed to extract opamFields is
// interpreted; other fields are parsed (so that their contents cannot be mistaken for fields) and then ignored.
func parseOpamFields(data []byte) (opamFields, error) {
	tokens, err := lexOpam(string(data))
	if err != nil {
		return opamFields{}, err
	}
	p := &opamParser{tokens: tokens}
	stmts := p.parseStatements(false)

	var out opamFields
	var isOpamFile bool
	for _, s := range stmts {
		switch s.name {
		case "opam-version":
			isOpamFile = true
		case "name":
			out.Name = firstString(s.value)
		case "version":
			out.Version = firstString(s.value)
		case "license":
			out.Licenses = allStrings(s.value)
		case "homepage":
			out.Homepage = firstString(s.value)
		case "depends":
			out.Depends = dependencies(s.value)
		case "url":
			if s.section == nil {
				continue
			}
			for _, f := range s.section {
				switch f.name {
				case "src", "archive", "http", "git", "local":
					out.URL = firstString(f.value)
				case "checksum":
					out.Checksums = allStrings(f.value)
				}
			}
		}
	}
	if !isOpamFile {
		return opamFields{}, errors.New("no opam-version field found")
	}
	return out, nil
}

type opamTokenKind int

const (
	tokString opamTokenKind = iota
	tokIdent
	tokOp
	tokColon
	tokLBracket
	tokRBracket
	tokLBrace
	tokRBrace
	tokLParen
	tokRParen
)

type opamToken struct {
	kind opamTokenKind
	text string
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || c == '-' || c == '+' || c == '.'
}

var opamPunctuation = map[byte]opamTokenKind{
	':': tokColon,
	'[': tokLBracket,
	']': tokRBracket,
	'{': tokLBrace,
	'}': tokRBrace,
	'(': tokLParen,
	')': tokRParen,
}

var opamTwoCharOperators = []string{">=", "<=", "!=", "+=", "=+", ":="}

type opamLexer struct {
	s      string
	i      int
	tokens []opamToken
}

func lexOpam(s string) ([]opamToken, error) {
	l := &opamLexer{s: s}
	for l.i < len(l.s) {
		if err := l.lexToken(); err != nil {
			return nil, err
		}
	}
	return l.tokens, nil
}

func (l *opamLexer) emit(kind opamTokenKind, text string, width int) {
	l.tokens = append(l.tokens, opamToken{kind: kind, text: text})
	l.i += width
}

func (l *opamLexer) lexToken() error {
	rest := l.s[l.i:]
	c := rest[0]
	switch {
	case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		l.i++
	case c == '#':
		l.skipLineComment()
	case strings.HasPrefix(rest, "(*"):
		return l.skipBlockComment()
	case strings.HasPrefix(rest, `"""`):
		return l.lexTripleQuotedString()
	case c == '"':
		return l.lexString()
	case hasTwoCharOperator(rest):
		l.emit(tokOp, rest[:2], 2)
	case isPunctuation(c):
		l.emit(opamPunctuation[c], string(c), 1)
	case strings.ContainsRune("=<>&|!?~", rune(c)):
		l.emit(tokOp, string(c), 1)
	case isIdentStart(c):
		l.lexIdent()
	default:
		return fmt.Errorf("unexpected character %q", c)
	}
	return nil
}

func isPunctuation(c byte) bool {
	_, ok := opamPunctuation[c]
	return ok
}

func hasTwoCharOperator(s string) bool {
	for _, op := range opamTwoCharOperators {
		if strings.HasPrefix(s, op) {
			return true
		}
	}
	return false
}

func (l *opamLexer) skipLineComment() {
	for l.i < len(l.s) && l.s[l.i] != '\n' {
		l.i++
	}
}

// skipBlockComment skips a (possibly nested) `(* ... *)` comment.
func (l *opamLexer) skipBlockComment() error {
	depth := 0
	for l.i < len(l.s) {
		switch {
		case strings.HasPrefix(l.s[l.i:], "(*"):
			depth++
			l.i += 2
		case strings.HasPrefix(l.s[l.i:], "*)"):
			depth--
			l.i += 2
			if depth == 0 {
				return nil
			}
		default:
			l.i++
		}
	}
	return errors.New("unterminated comment")
}

func (l *opamLexer) lexTripleQuotedString() error {
	end := strings.Index(l.s[l.i+3:], `"""`)
	if end < 0 {
		return errors.New("unterminated triple-quoted string")
	}
	l.emit(tokString, l.s[l.i+3:l.i+3+end], 3+end+3)
	return nil
}

func (l *opamLexer) lexString() error {
	var b strings.Builder
	for i := l.i + 1; i < len(l.s); i++ {
		switch l.s[i] {
		case '\\':
			if i+1 < len(l.s) {
				i++
				b.WriteByte(l.s[i])
			}
		case '"':
			l.tokens = append(l.tokens, opamToken{kind: tokString, text: b.String()})
			l.i = i + 1
			return nil
		default:
			b.WriteByte(l.s[i])
		}
	}
	return errors.New("unterminated string")
}

func (l *opamLexer) lexIdent() {
	start := l.i
	for l.i < len(l.s) {
		c := l.s[l.i]
		// package variables such as `ocaml:version` are a single identifier
		if isIdentChar(c) || (c == ':' && l.i+1 < len(l.s) && isIdentStart(l.s[l.i+1])) {
			l.i++
			continue
		}
		break
	}
	l.tokens = append(l.tokens, opamToken{kind: tokIdent, text: l.s[start:l.i]})
}

// opamNode is a parsed value: a string, identifier or operator leaf, or a list `[...]` / group `(...)` of nodes.
// option holds the contents of a trailing `{...}` filter or constraint.
type opamNode struct {
	kind     opamTokenKind
	text     string
	children []opamNode
	option   []opamNode
}

type opamStatement struct {
	name    string
	value   []opamNode
	section []opamStatement
}

type opamParser struct {
	tokens []opamToken
	pos    int
}

func (p *opamParser) peek(offset int) *opamToken {
	if p.pos+offset < len(p.tokens) {
		return &p.tokens[p.pos+offset]
	}
	return nil
}

func (p *opamParser) next() opamToken {
	t := p.tokens[p.pos]
	p.pos++
	return t
}

func (p *opamParser) is(offset int, kind opamTokenKind) bool {
	t := p.peek(offset)
	return t != nil && t.kind == kind
}

// parseStatements parses field bindings (`name: value`) and sections (`name ["label"] { ... }`).
func (p *opamParser) parseStatements(inSection bool) []opamStatement {
	var stmts []opamStatement
	for p.pos < len(p.tokens) {
		if inSection && p.is(0, tokRBrace) {
			p.next()
			return stmts
		}
		switch {
		case p.is(0, tokIdent) && p.is(1, tokColon):
			name := p.next().text
			p.next()
			stmts = append(stmts, opamStatement{name: name, value: p.parseValue()})
		case p.is(0, tokIdent) && p.is(1, tokLBrace):
			name := p.next().text
			p.next()
			stmts = append(stmts, opamStatement{name: name, section: p.parseStatements(true)})
		case p.is(0, tokIdent) && p.is(1, tokString) && p.is(2, tokLBrace):
			name := p.next().text
			p.next()
			p.next()
			stmts = append(stmts, opamStatement{name: name, section: p.parseStatements(true)})
		default:
			// not a statement: skip the token so a malformed construct cannot stall parsing
			p.next()
		}
	}
	return stmts
}

// parseValue parses `atom [option] { operator atom [option] }`.
func (p *opamParser) parseValue() []opamNode {
	var nodes []opamNode
	for {
		atom, ok := p.parseAtom()
		if !ok {
			return nodes
		}
		nodes = append(nodes, atom)
		if !p.is(0, tokOp) {
			return nodes
		}
	}
}

func (p *opamParser) parseAtom() (opamNode, bool) {
	t := p.peek(0)
	if t == nil {
		return opamNode{}, false
	}
	var n opamNode
	switch t.kind {
	case tokString, tokIdent:
		p.next()
		n = opamNode{kind: t.kind, text: t.text}
	case tokOp:
		p.next()
		n = opamNode{kind: tokOp, text: t.text}
		return n, true
	case tokLBracket:
		p.next()
		n = opamNode{kind: tokLBracket, children: p.parseUntil(tokRBracket)}
	case tokLParen:
		p.next()
		n = opamNode{kind: tokLParen, children: p.parseUntil(tokRParen)}
	default:
		return opamNode{}, false
	}
	if p.is(0, tokLBrace) {
		p.next()
		n.option = p.parseUntil(tokRBrace)
	}
	return n, true
}

// parseUntil parses atoms until the given closing token (which is consumed).
func (p *opamParser) parseUntil(closing opamTokenKind) []opamNode {
	var nodes []opamNode
	for p.pos < len(p.tokens) {
		if p.is(0, closing) {
			p.next()
			return nodes
		}
		atom, ok := p.parseAtom()
		if !ok {
			// unexpected token (e.g. a stray closing delimiter): skip it
			p.next()
			continue
		}
		nodes = append(nodes, atom)
	}
	return nodes
}

func firstString(nodes []opamNode) string {
	for _, n := range nodes {
		switch n.kind {
		case tokString:
			return n.text
		case tokLBracket:
			if s := firstString(n.children); s != "" {
				return s
			}
		}
	}
	return ""
}

func allStrings(nodes []opamNode) []string {
	var out []string
	for _, n := range nodes {
		switch n.kind {
		case tokString:
			out = append(out, n.text)
		case tokLBracket:
			out = append(out, allStrings(n.children)...)
		}
	}
	return out
}

// dependencies extracts every package named in a depends formula, including all alternatives of a disjunction.
func dependencies(nodes []opamNode) []opamDependency {
	var out []opamDependency
	for _, n := range nodes {
		switch n.kind {
		case tokString:
			out = append(out, opamDependency{Name: n.text, Version: pinnedVersion(n.option)})
		case tokLBracket, tokLParen:
			out = append(out, dependencies(n.children)...)
		}
	}
	return out
}

// pinnedVersion returns X for a constraint of the form `= "X"` (optionally combined with filters, e.g.
// `{= "X" & with-test}`). A binary comparison such as `os = "linux"` is not a version pin.
func pinnedVersion(option []opamNode) string {
	for i, n := range option {
		if n.kind != tokOp || n.text != "=" || i+1 >= len(option) || option[i+1].kind != tokString {
			continue
		}
		if i == 0 || (option[i-1].kind == tokOp && (option[i-1].text == "&" || option[i-1].text == "|")) {
			return option[i+1].text
		}
	}
	return ""
}
