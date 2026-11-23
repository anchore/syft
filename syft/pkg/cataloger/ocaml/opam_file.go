package ocaml

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/internal/parsing"
)

var errTooDeep = fmt.Errorf("nesting deeper than %d levels", parsing.MaxDepth)

// utf8BOM is ignored at the start of a file, which some editors write.
const utf8BOM = "\uFEFF"

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
// exact version (e.g. `"lwt" {= "5.4.2"}`), as in opam lock files. Development is set for dependencies that are only
// needed to test, document or develop the package (`{with-test}`, `{with-doc}`, `{with-dev-setup}`).
type opamDependency struct {
	Name        string
	Version     string
	Development bool
}

// parseOpamFields parses the opam file format. Only the subset of the grammar needed to extract opamFields is
// interpreted; other fields are parsed (so that their contents cannot be mistaken for fields) and then ignored.
func parseOpamFields(data []byte) (opamFields, error) {
	tokens, err := lexOpam(strings.TrimPrefix(string(data), utf8BOM))
	if err != nil {
		return opamFields{}, err
	}
	p := &opamParser{tokens: tokens}
	stmts := p.parseStatements(false)
	if p.err != nil {
		return opamFields{}, p.err
	}

	var out opamFields
	var isOpamFile bool
	for _, s := range stmts {
		switch s.name {
		case "opam-version":
			isOpamFile = true
		case "name":
			out.Name = firstString(s.value)
		case "version":
			out.Version = knownVersion(firstString(s.value))
		case "license":
			out.Licenses = allStrings(s.value)
		case "homepage":
			out.Homepage = firstString(s.value)
		case "depends":
			out.Depends = dependencies(s.value, false)
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
	return l.lexQuoted(`"""`)
}

func (l *opamLexer) lexString() error {
	return l.lexQuoted(`"`)
}

// lexQuoted reads a string delimited by quote, decoding its escape sequences.
func (l *opamLexer) lexQuoted(quote string) error {
	start := l.i + len(quote)
	for i := start; i < len(l.s); i++ {
		switch {
		case l.s[i] == '\\':
			i++
		case strings.HasPrefix(l.s[i:], quote):
			l.emit(tokString, unescapeOpamString(l.s[start:i]), i+len(quote)-l.i)
			return nil
		}
	}
	return errors.New("unterminated string")
}

var opamSimpleEscapes = map[byte]byte{'\\': '\\', '"': '"', '\'': '\'', 'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', ' ': ' '}

// unescapeOpamString decodes the escape sequences of the opam file format: \\ \" \' \n \r \t \b and "\ ", decimal
// \ddd and hexadecimal \xhh codes, and a backslash at the end of a line, which skips the line break and the indentation
// that follows. Other sequences are kept as written.
func unescapeOpamString(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		switch {
		case opamSimpleEscapes[next] != 0:
			b.WriteByte(opamSimpleEscapes[next])
			i++
		case next == '\n' || (next == '\r' && i+2 < len(s) && s[i+2] == '\n'):
			i++
			if next == '\r' {
				i++
			}
			for i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
				i++
			}
		case i+3 < len(s) && isDigits(s[i+1:i+4]):
			if c, err := strconv.ParseUint(s[i+1:i+4], 10, 8); err == nil {
				b.WriteByte(byte(c))
				i += 3
			} else {
				b.WriteByte(s[i])
			}
		case next == 'x' && i+3 < len(s):
			if c, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(c))
				i += 3
			} else {
				b.WriteByte(s[i])
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
	depth  int
	err    error
}

// descend enters a nested list, group, option or section. Beyond parsing.MaxDepth it records errTooDeep and skips to
// the end of the input, which ends every parsing loop; this bounds both the parser and the functions walking its tree.
func (p *opamParser) descend() bool {
	p.depth++
	if p.depth > parsing.MaxDepth {
		p.err = errTooDeep
		p.pos = len(p.tokens)
		return false
	}
	return true
}

// parseNested parses the contents of a nested list, group or option up to the given closing token.
func (p *opamParser) parseNested(closing opamTokenKind) []opamNode {
	defer func() { p.depth-- }()
	if !p.descend() {
		return nil
	}
	return p.parseUntil(closing)
}

// parseSection parses the statements of a section up to its closing brace.
func (p *opamParser) parseSection() []opamStatement {
	defer func() { p.depth-- }()
	if !p.descend() {
		return nil
	}
	return p.parseStatements(true)
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
			stmts = append(stmts, opamStatement{name: name, section: p.parseSection()})
		case p.is(0, tokIdent) && p.is(1, tokString) && p.is(2, tokLBrace):
			name := p.next().text
			p.next()
			p.next()
			stmts = append(stmts, opamStatement{name: name, section: p.parseSection()})
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
		n = opamNode{kind: tokLBracket, children: p.parseNested(tokRBracket)}
	case tokLParen:
		p.next()
		n = opamNode{kind: tokLParen, children: p.parseNested(tokRParen)}
	default:
		return opamNode{}, false
	}
	if p.is(0, tokLBrace) {
		p.next()
		n.option = p.parseNested(tokRBrace)
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

// dependencies extracts every package named in a depends formula, including all alternatives of a disjunction. A
// filter on a group applies to every package in it.
func dependencies(nodes []opamNode, development bool) []opamDependency {
	var out []opamDependency
	for _, n := range nodes {
		dev := development || isDevelopmentOnly(n.option)
		switch n.kind {
		case tokString:
			out = append(out, opamDependency{Name: n.text, Version: pinnedVersion(n.option), Development: dev})
		case tokLBracket, tokLParen:
			out = append(out, dependencies(n.children, dev)...)
		}
	}
	return out
}

// developmentVariables are the filter variables that are only true when a package is tested, documented or set up
// for development.
var developmentVariables = map[string]bool{"with-test": true, "with-doc": true, "with-dev-setup": true}

// isDevelopmentOnly reports whether a constraint requires one of the developmentVariables, e.g. `{with-test}` or
// `{= "2.2.5" & with-doc}`. A disjunction (`{with-test | build}`) may hold without them, so it does not count. Neither
// do a negation (`{!with-test}`, which holds when not testing), an undefined variable test (`{?with-test}`) or a
// comparison (`{with-test = false}`): such a dependency is kept.
func isDevelopmentOnly(option []opamNode) bool {
	if hasDisjunction(option) {
		return false
	}
	for i, n := range option {
		if n.kind != tokIdent || !developmentVariables[n.text] {
			continue
		}
		if i > 0 && option[i-1].kind == tokOp && (option[i-1].text == "!" || option[i-1].text == "?") {
			continue
		}
		if i+1 < len(option) && option[i+1].kind == tokOp && (option[i+1].text == "=" || option[i+1].text == "!=") {
			continue
		}
		return true
	}
	return false
}

func hasDisjunction(option []opamNode) bool {
	for _, n := range option {
		if n.kind == tokOp && n.text == "|" {
			return true
		}
	}
	return false
}

// pinnedVersion returns X for a constraint of the form `= "X"` (optionally combined with filters, e.g.
// `{= "X" & with-test}`). A binary comparison such as `os = "linux"` is not a version pin, and neither is a
// disjunction such as `{= "1" | = "2"}`.
func pinnedVersion(option []opamNode) string {
	if hasDisjunction(option) {
		return ""
	}
	for i, n := range option {
		if n.kind != tokOp || n.text != "=" || i+1 >= len(option) || option[i+1].kind != tokString {
			continue
		}
		if i == 0 || (option[i-1].kind == tokOp && option[i-1].text == "&") {
			return option[i+1].text
		}
	}
	return ""
}
