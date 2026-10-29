package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	decodeLineRe = regexp.MustCompile(`^line (\d+): (.*)$`)
	unmarshalRe  = regexp.MustCompile(`^cannot unmarshal !!(\w+) (?:.* )?into (\S+)$`)
)

// describeDecodeError rewrites a decode error so it never quotes a scalar
// (which may be or contain a substituted env value): each problem is
// reported by key path and line in the file as written, plus the reason.
// out is the re-encoded document the decoder saw (its line numbers are
// not the file's); root is the substituted tree parsed from the file.
func describeDecodeError(err error, out []byte, root *yaml.Node) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return errors.New(elideQuoted(err.Error()))
	}
	var outRoot yaml.Node
	_ = yaml.Unmarshal(out, &outRoot)
	msgs := make([]string, 0, len(te.Errors))
	for _, e := range te.Errors {
		m := decodeLineRe.FindStringSubmatch(e)
		if m == nil {
			msgs = append(msgs, elideQuoted(e))
			continue
		}
		reason := decodeReason(m[2])
		n, _ := strconv.Atoi(m[1])
		where := "a value"
		if p := pathAtLine(&outRoot, n, nil); p != nil {
			where = formatPath(p)
			if ln := lineAtPath(root, p); ln > 0 {
				where += fmt.Sprintf(" (line %d)", ln)
			}
		}
		msgs = append(msgs, where+": "+reason)
	}
	return errors.New(strings.Join(msgs, "; "))
}

// decodeReason turns a yaml.v3 problem into a reason without the value.
func decodeReason(s string) string {
	if m := unmarshalRe.FindStringSubmatch(s); m != nil {
		what := map[string]string{"str": "a string", "int": "an integer", "float": "a number",
			"bool": "a boolean", "map": "a mapping", "seq": "a list", "null": "null"}[m[1]]
		if what == "" {
			what = "a " + m[1]
		}
		into := map[string]string{"int": "an integer", "int64": "an integer", "uint16": "an integer",
			"float64": "a number", "bool": "true or false", "string": "a string"}[m[2]]
		if into == "" {
			into = m[2]
		}
		return "invalid value: " + what + " where " + into + " is expected"
	}
	return elideQuoted(s)
}

// elideQuoted replaces every quoted token (`...` or "...") in s.
func elideQuoted(s string) string {
	s = backtickRe.ReplaceAllString(s, "(value elided)")
	return dquoteRe.ReplaceAllString(s, "(value elided)")
}

type pathElem struct {
	key string
	idx int // -1 for a mapping key
}

// pathAtLine returns the path to the first node (in document order) whose
// key or scalar value is on line n, or nil.
func pathAtLine(n *yaml.Node, line int, path []pathElem) []pathElem {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if p := pathAtLine(c, line, path); p != nil {
				return p
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			p := append(append([]pathElem{}, path...), pathElem{key: k.Value, idx: -1})
			if k.Line == line || (v.Kind == yaml.ScalarNode && v.Line == line) {
				return p
			}
			if r := pathAtLine(v, line, p); r != nil {
				return r
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			p := append(append([]pathElem{}, path...), pathElem{idx: i})
			if c.Kind == yaml.ScalarNode && c.Line == line {
				return p
			}
			if r := pathAtLine(c, line, p); r != nil {
				return r
			}
		}
	}
	return nil
}

// lineAtPath returns the line of path's last key or element in n, or 0.
func lineAtPath(n *yaml.Node, path []pathElem) int {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	line := 0
	for _, e := range path {
		switch {
		case e.idx < 0 && n.Kind == yaml.MappingNode:
			found := false
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == e.key {
					line, n, found = n.Content[i].Line, n.Content[i+1], true
					break
				}
			}
			if !found {
				return 0
			}
		case e.idx >= 0 && n.Kind == yaml.SequenceNode && e.idx < len(n.Content):
			n = n.Content[e.idx]
			line = n.Line
		default:
			return 0
		}
	}
	return line
}

func formatPath(p []pathElem) string {
	var b strings.Builder
	for _, e := range p {
		if e.idx >= 0 {
			fmt.Fprintf(&b, "[%d]", e.idx)
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(e.key)
	}
	return b.String()
}
