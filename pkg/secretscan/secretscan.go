// Package secretscan is Chimera's secret gate: built-in credential rules plus
// operator-supplied terms (tenant values and denylist entries).
//
// A Finding names a path, line, column, and rule. It never carries the matched
// bytes, so nothing built from Findings can echo a secret or tenant term.
package secretscan

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Built-in rule IDs.
const (
	RuleCloudKey       = "cloud-key"
	RuleForgeToken     = "forge-token"
	RuleChatToken      = "chat-token"
	RulePrivateKey     = "private-key"
	RuleJWT            = "jwt"
	RuleAssignedSecret = "assigned-secret"
)

// Term rule IDs used by callers that add operator-supplied terms.
const (
	RuleTenantTerm       = "tenant-term"
	RuleDenylistTerm     = "denylist-term"
	RuleConfiguredSecret = "configured-secret"
)

// minAssignedEntropy is the Shannon entropy (bits per byte) a value assigned to a
// key|secret|token|password name must reach to count as a secret.
const minAssignedEntropy = 3.5

type rule struct {
	id string
	re *regexp.Regexp
	// group selects the submatch whose position is reported and, for entropy
	// rules, whose bytes are measured. 0 means the whole match.
	group   int
	entropy bool
}

var builtin = []rule{
	{id: RuleCloudKey, re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b`)},
	{id: RuleCloudKey, re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{id: RuleForgeToken, re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{id: RuleForgeToken, re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`)},
	{id: RuleForgeToken, re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{id: RuleChatToken, re: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`)},
	{id: RuleChatToken, re: regexp.MustCompile(`\bxapp-[0-9]-[A-Za-z0-9-]{10,}\b`)},
	{id: RuleChatToken, re: regexp.MustCompile(`hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{8,}`)},
	{id: RuleChatToken, re: regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`)},
	{id: RulePrivateKey, re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
	{id: RuleJWT, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{
		id:      RuleAssignedSecret,
		re:      regexp.MustCompile(`(?i)[a-z0-9_.-]*(?:key|secret|token|password|passwd)[a-z0-9_.-]*["']?\s*[:=]+\s*["']?([A-Za-z0-9+/_=.~-]{20,})`),
		group:   1,
		entropy: true,
	},
}

// Term is an operator-supplied literal matched case-insensitively (ASCII) at
// word boundaries.
type Term struct {
	Value string
	Rule  string
}

// Finding locates one match. Line and Col are 1-based; Col counts bytes.
type Finding struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Col  int    `json:"col"`
	Rule string `json:"rule"`
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d:%d %s", f.Path, f.Line, f.Col, f.Rule) }

// Scanner applies the built-in rules and a fixed set of terms.
type Scanner struct {
	terms []Term // Value already ASCII-lowercased
}

// New returns a Scanner with every built-in rule plus terms. Empty and
// whitespace-only terms are ignored; duplicates collapse to the first rule.
func New(terms []Term) *Scanner {
	seen := map[string]bool{}
	s := &Scanner{}
	for _, t := range terms {
		v := strings.TrimSpace(t.Value)
		if v == "" {
			continue
		}
		v = string(foldASCII([]byte(v)))
		if seen[v] {
			continue
		}
		seen[v] = true
		s.terms = append(s.terms, Term{Value: v, Rule: t.Rule})
	}
	return s
}

// TermCount reports how many distinct terms the scanner holds.
func (s *Scanner) TermCount() int { return len(s.terms) }

// Scan reports every finding in data, sorted by line, column, then rule.
// Binary data is scanned as bytes.
func (s *Scanner) Scan(path string, data []byte) []Finding {
	lines := newLineIndex(data)
	type key struct {
		off  int
		rule string
	}
	hits := map[key]bool{}
	for _, r := range builtin {
		for _, m := range r.re.FindAllSubmatchIndex(data, -1) {
			start, end := m[2*r.group], m[2*r.group+1]
			if start < 0 {
				continue
			}
			if r.entropy && entropy(data[start:end]) < minAssignedEntropy {
				continue
			}
			hits[key{start, r.id}] = true
		}
	}
	if len(s.terms) > 0 {
		folded := foldASCII(data)
		for _, t := range s.terms {
			for _, off := range wordMatches(folded, []byte(t.Value)) {
				hits[key{off, t.Rule}] = true
			}
		}
	}
	out := make([]Finding, 0, len(hits))
	for k := range hits {
		line, col := lines.position(k.off)
		out = append(out, Finding{Path: path, Line: line, Col: col, Rule: k.rule})
	}
	Sort(out)
	return out
}

// Sort orders findings by path, line, column, then rule.
func Sort(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		return a.Rule < b.Rule
	})
}

// Rules returns the distinct rule IDs present in fs, sorted.
func Rules(fs []Finding) []string {
	set := map[string]bool{}
	for _, f := range fs {
		set[f.Rule] = true
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func isWord(b byte) bool {
	return b == '_' || ('0' <= b && b <= '9') || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

// wordMatches returns every offset where term occurs in data with a word
// boundary on each side whose edge character is itself a word character.
func wordMatches(data, term []byte) []int {
	var out []int
	needStart, needEnd := isWord(term[0]), isWord(term[len(term)-1])
	for from := 0; from+len(term) <= len(data); {
		i := indexFrom(data, term, from)
		if i < 0 {
			break
		}
		end := i + len(term)
		okStart := !needStart || i == 0 || !isWord(data[i-1])
		okEnd := !needEnd || end == len(data) || !isWord(data[end])
		if okStart && okEnd {
			out = append(out, i)
		}
		from = i + 1
	}
	return out
}

func indexFrom(data, term []byte, from int) int {
	i := strings.Index(string(data[from:]), string(term))
	if i < 0 {
		return -1
	}
	return from + i
}

// foldASCII lowercases ASCII letters without changing byte offsets.
func foldASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	n := float64(len(b))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

type lineIndex []int // offsets of '\n'

func newLineIndex(data []byte) lineIndex {
	var idx lineIndex
	for i, c := range data {
		if c == '\n' {
			idx = append(idx, i)
		}
	}
	return idx
}

func (l lineIndex) position(off int) (line, col int) {
	n := sort.SearchInts(l, off) // newlines strictly before off
	start := 0
	if n > 0 {
		start = l[n-1] + 1
	}
	return n + 1, off - start + 1
}
