package web

// GET/PUT /api/v1/config work on the config FILE as written (a yaml.Node
// tree), never on the decoded Config: the decoded one has ${VAR} already
// substituted, so writing it back would turn environment secrets into
// plaintext on disk.
//
// Masking (fail closed): a scalar is sensitive when it sits
//   - under providers.<name>, except `type` and the fields the DNS
//     registry's schema for that type declares non-secret (types the
//     registry does not know, e.g. lego challenge providers: every field);
//   - at issuers.*.eab_hmac, sources.truenas.api_key, notifications
//     webhooks[].url/secret/headers, ntfy[].topic/token/password,
//     smtp[].password;
//   - under any key whose name looks secret (password, secret, token, key
//     names such as api_key, hmac, users, ...), anywhere: this covers
//     middleware basicAuth users.
// A sensitive scalar is shown as-is only when it is a reference: a
// "secret:" ref or exactly one ${VAR} placeholder without a default.
// Everything else becomes Masked. PUT replaces each Masked scalar with the
// value at the same path in the current file (sequence entries by index);
// a Masked scalar where the file has none, or in a non-sensitive field, is
// an error.

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ajthom90/doorwarden/internal/dns"
)

// Masked replaces secret values in GET /api/v1/config; sent back in a PUT
// it means "keep the current value".
const Masked = "<masked>"

var (
	refPlaceholder = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)
	secretKeyRe    = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api_?key|access_?key|private|hmac|credential|users)`)
	backtickRe     = regexp.MustCompile("`[^`]*`")
	dquoteRe       = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	squoteRe       = regexp.MustCompile(`'[^']*'`)
)

type docPath []string

func (p docPath) String() string { return strings.Join(p, ".") }

func (p docPath) with(s string) docPath {
	out := make(docPath, len(p)+1)
	copy(out, p)
	out[len(p)] = s
	return out
}

// sensitiveField reports whether the mapping value at path (whose last
// element is the key) is secret. ptype is the provider type when path is
// under providers.<name>.
func sensitiveField(path docPath, ptype string) bool {
	n := len(path)
	if n == 0 {
		return false
	}
	key := path[n-1]
	if n >= 3 && path[0] == "providers" {
		if n == 3 && key == "type" {
			return false
		}
		if n == 3 {
			if sch, ok := dns.SchemaFor(ptype); ok {
				for _, f := range sch.Fields {
					if f.Name == key {
						return f.Secret || secretKeyRe.MatchString(key)
					}
				}
			}
		}
		return true
	}
	if n == 3 && path[0] == "issuers" && key == "eab_hmac" {
		return true
	}
	if n == 3 && path[0] == "sources" && path[1] == "truenas" && key == "api_key" {
		return true
	}
	if n >= 4 && path[0] == "notifications" {
		switch path[1] {
		case "webhooks":
			if key == "url" || key == "secret" || key == "headers" || (n >= 5 && path[3] == "headers") {
				return true
			}
		case "ntfy":
			if key == "topic" || key == "token" || key == "password" {
				return true
			}
		case "smtp":
			if key == "password" {
				return true
			}
		}
	}
	return secretKeyRe.MatchString(key)
}

func isReference(v string) bool {
	return strings.HasPrefix(v, dns.SecretPrefix) || refPlaceholder.MatchString(v)
}

// walkDoc calls fn for every scalar with its path and sensitivity.
func walkDoc(n *yaml.Node, path docPath, sens bool, ptype string, fn func(*yaml.Node, docPath, bool) error) error {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := walkDoc(c, path, sens, ptype, fn); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if len(path) == 2 && path[0] == "providers" {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "type" {
					ptype = n.Content[i+1].Value
				}
			}
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := path.with(n.Content[i].Value)
			if err := walkDoc(n.Content[i+1], p, sens || sensitiveField(p, ptype), ptype, fn); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			if err := walkDoc(c, path.with("["+strconv.Itoa(i)+"]"), sens, ptype, fn); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		return fn(n, path, sens)
	case yaml.AliasNode:
		// An alias could smuggle a secret into a plain field; refuse.
		return fmt.Errorf("config: YAML aliases are not supported (at %s)", path)
	}
	return nil
}

func parseDoc(raw []byte) (*yaml.Node, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, errors.New("config is not valid YAML: " + scrubConfigError(err.Error(), nil))
	}
	if root.Kind == 0 {
		root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	return &root, nil
}

func encodeDoc(root *yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return b.Bytes(), nil
}

func setMasked(n *yaml.Node) {
	n.Value, n.Tag, n.Style = Masked, "!!str", yaml.SingleQuotedStyle
	n.LineComment, n.HeadComment, n.FootComment = "", "", ""
}

// MaskConfig returns raw with every sensitive value masked.
func MaskConfig(raw []byte) ([]byte, error) {
	root, err := parseDoc(raw)
	if err != nil {
		return nil, err
	}
	err = walkDoc(root, nil, false, "", func(n *yaml.Node, _ docPath, sens bool) error {
		if sens && !(n.Tag == "!!str" || n.ShortTag() == "!!str") {
			setMasked(n) // numbers/bools under secret keys too
			return nil
		}
		if sens && !isReference(n.Value) {
			setMasked(n)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return encodeDoc(root)
}

func lookup(n *yaml.Node, path docPath) *yaml.Node {
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		n = n.Content[0]
	}
	for _, el := range path {
		switch n.Kind {
		case yaml.MappingNode:
			var next *yaml.Node
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == el {
					next = n.Content[i+1]
				}
			}
			if next == nil {
				return nil
			}
			n = next
		case yaml.SequenceNode:
			if !strings.HasPrefix(el, "[") {
				return nil
			}
			i, err := strconv.Atoi(strings.Trim(el, "[]"))
			if err != nil || i < 0 || i >= len(n.Content) {
				return nil
			}
			n = n.Content[i]
		default:
			return nil
		}
	}
	return n
}

// MergeMasked returns newRaw with every Masked scalar replaced by the value
// at the same path in oldRaw.
func MergeMasked(newRaw, oldRaw []byte) ([]byte, error) {
	nr, err := parseDoc(newRaw)
	if err != nil {
		return nil, err
	}
	or, err := parseDoc(oldRaw)
	if err != nil {
		return nil, errors.New("the current config file is not valid YAML")
	}
	err = walkDoc(nr, nil, false, "", func(n *yaml.Node, path docPath, sens bool) error {
		if n.Value != Masked {
			return nil
		}
		if !sens {
			return fmt.Errorf("%s: %s is only allowed in secret fields", path, Masked)
		}
		old := lookup(or, path)
		if old == nil || old.Kind != yaml.ScalarNode || old.Value == Masked {
			return fmt.Errorf("%s: %s has no current value to keep; enter the value", path, Masked)
		}
		n.Value, n.Tag, n.Style = old.Value, old.Tag, old.Style
		return nil
	})
	if err != nil {
		return nil, err
	}
	return encodeDoc(nr)
}

// sensitiveValues returns every sensitive scalar value of raw (for
// scrubbing error messages).
func sensitiveValues(raw []byte) []string {
	root, err := parseDoc(raw)
	if err != nil {
		return nil
	}
	var out []string
	_ = walkDoc(root, nil, false, "", func(n *yaml.Node, _ docPath, sens bool) error {
		if sens && n.Value != "" && !isReference(n.Value) {
			out = append(out, n.Value)
		}
		return nil
	})
	return out
}

// scrubConfigError removes values from a config error so only paths and
// reasons remain: quoted excerpts (yaml.v3 echoes scalars in backticks,
// Validate quotes values with %q) and every known secret.
func scrubConfigError(msg string, secrets []string) string {
	msg = backtickRe.ReplaceAllString(msg, "`…`")
	msg = dquoteRe.ReplaceAllString(msg, `"…"`)
	msg = squoteRe.ReplaceAllString(msg, `'…'`)
	for _, s := range secrets {
		if len(s) >= 3 {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	if len(msg) > 2000 {
		msg = msg[:2000] + "…"
	}
	return msg
}
