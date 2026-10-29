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
// Everything else becomes Masked, and comments are dropped. PUT replaces
// each Masked scalar with the stored value of the same field (see
// MergeMasked: list entries by identity, refused across a destination
// change); a Masked scalar where the file has none, or in a non-sensitive
// field, is an error.

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
	secretKeyRe    = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|key|private|hmac|credential|users|authorization|cookie)`)
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

// stripComments removes every comment (they may quote secrets).
func stripComments(n *yaml.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, c := range n.Content {
		stripComments(c)
	}
}

// MaskConfig returns raw with every sensitive value masked and all
// comments removed.
func MaskConfig(raw []byte) ([]byte, error) {
	root, err := parseDoc(raw)
	if err != nil {
		return nil, err
	}
	stripComments(root)
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

// destKeys name where a secret is sent. A masked secret is only kept when
// every destination field in its mapping and the mappings above it is
// unchanged from the stored file.
var destKeys = map[string]bool{
	"url": true, "uri": true, "host": true, "hostname": true, "server": true, "servers": true,
	"endpoint": true, "address": true, "base_url": true, "api_url": true, "nameserver": true,
	"type": true, "port": true,
}

// identityKeys identify a list entry (matched by these, not by index).
var identityKeys = []string{"name", "id", "url", "host", "server", "endpoint", "address", "topic", "username"}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalarVal(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	return n.Value, true
}

// destChanged reports whether a destination field differs between the new
// mapping n and the stored mapping o. A masked destination counts as
// unchanged (it is itself kept from o).
func destChanged(n, o *yaml.Node) bool {
	if o == nil || o.Kind != yaml.MappingNode {
		return true
	}
	for k := range destKeys {
		nv, o2 := mapGet(n, k), mapGet(o, k)
		if nv == nil && o2 == nil {
			continue
		}
		if nv == nil || o2 == nil {
			return true
		}
		if v, ok := scalarVal(nv); ok && v == Masked {
			continue
		}
		a, err1 := encodeDoc(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{plain(nv)}})
		b, err2 := encodeDoc(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{plain(o2)}})
		if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
			return true
		}
	}
	return false
}

// plain copies n without styles or comments (for comparison).
func plain(n *yaml.Node) *yaml.Node {
	c := &yaml.Node{Kind: n.Kind, Tag: n.ShortTag(), Value: n.Value}
	for _, x := range n.Content {
		c.Content = append(c.Content, plain(x))
	}
	return c
}

// identity is the entry's identity: its identity fields that are not
// masked in the new entry (keys; nil: every identity key), with their
// values ("" + false when absent).
func identity(n *yaml.Node, keys []string) map[string]string {
	if keys == nil {
		keys = identityKeys
	}
	id := map[string]string{}
	for _, k := range keys {
		if v, ok := scalarVal(mapGet(n, k)); ok && v != Masked {
			id[k] = v
		}
	}
	return id
}

func sameIdentity(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// plainFieldsEqual reports whether every scalar that is not masked in n is
// equal in o at the same key (one mapping level).
func plainFieldsEqual(n, o *yaml.Node) bool {
	if n.Kind != yaml.MappingNode || o.Kind != yaml.MappingNode || len(n.Content) != len(o.Content) {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		v, ok := scalarVal(n.Content[i+1])
		if !ok || v == Masked {
			continue
		}
		if ov, ok := scalarVal(mapGet(o, n.Content[i].Value)); !ok || ov != v {
			return false
		}
	}
	return true
}

// matchEntry finds the stored entry for new sequence entry i: by identity
// when the entries are mappings with one; a unique identity match wins,
// several are disambiguated only by the same index with equal plain
// fields. Scalar entries match by index only while the list keeps its
// length. nil: no (unambiguous) match.
func matchEntry(ns, os *yaml.Node, i int) *yaml.Node {
	if os == nil || os.Kind != yaml.SequenceNode {
		return nil
	}
	n := ns.Content[i]
	if n.Kind != yaml.MappingNode {
		if len(ns.Content) == len(os.Content) {
			return os.Content[i]
		}
		return nil
	}
	// Compare only the identity fields the new entry states in clear: a
	// masked one is itself kept from the matched entry.
	keys := []string{} // non-nil: an empty set compares nothing
	for _, k := range identityKeys {
		if v, ok := scalarVal(mapGet(n, k)); !ok || v != Masked {
			keys = append(keys, k)
		}
	}
	id := identity(n, keys)
	var cands []int
	for j, o := range os.Content {
		if o.Kind == yaml.MappingNode && sameIdentity(id, identity(o, keys)) {
			cands = append(cands, j)
		}
	}
	if len(cands) == 1 && len(id) > 0 {
		return os.Content[cands[0]]
	}
	for _, j := range cands {
		if j == i && plainFieldsEqual(n, os.Content[j]) {
			return os.Content[j]
		}
	}
	return nil
}

type merger struct{}

// merge walks the new node n alongside its stored counterpart o (nil when
// none). changed: a destination above has changed.
func (m merger) merge(n, o *yaml.Node, path docPath, sens bool, ptype string, changed bool) error {
	switch n.Kind {
	case yaml.DocumentNode:
		for i, c := range n.Content {
			var oc *yaml.Node
			if o != nil && i < len(o.Content) {
				oc = o.Content[i]
			}
			if err := m.merge(c, oc, path, sens, ptype, changed); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if o != nil && o.Kind != yaml.MappingNode {
			o = nil
		}
		if len(path) == 2 && path[0] == "providers" {
			if v, ok := scalarVal(mapGet(n, "type")); ok {
				ptype = v
			}
		}
		changed = changed || destChanged(n, o)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			p := path.with(k)
			if err := m.merge(n.Content[i+1], mapGet(o, k), p, sens || sensitiveField(p, ptype), ptype, changed); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			oc := matchEntry(n, o, i)
			// No stored counterpart: anything masked below must be
			// re-entered.
			if err := m.merge(c, oc, path.with("["+strconv.Itoa(i)+"]"), sens, ptype, changed || oc == nil); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if n.Value == Masked {
			if !sens {
				return fmt.Errorf("%s: %s is only allowed in secret fields", path, Masked)
			}
			if o == nil || o.Kind != yaml.ScalarNode || o.Value == Masked {
				return fmt.Errorf("%s: %s has no current value to keep; re-enter the secret", path, Masked)
			}
			if changed {
				return fmt.Errorf("%s: its destination or entry changed; re-enter the secret", path)
			}
			n.Value, n.Tag, n.Style = o.Value, o.Tag, o.Style
			return nil
		}
		// ${VAR} is expanded at load time; in a plain field the result
		// would be echoed by the API. Only secret fields may gain one.
		if !sens && strings.Contains(n.Value, "${") {
			if ov, ok := scalarVal(o); !ok || ov != n.Value {
				return fmt.Errorf("%s: ${...} environment references are only allowed in secret fields", path)
			}
		}
	case yaml.AliasNode:
		return fmt.Errorf("config: YAML aliases are not supported (at %s)", path)
	}
	return nil
}

// MergeMasked returns newRaw with every Masked scalar replaced by the
// stored value of the same field in oldRaw. Mappings match by key, list
// entries by identity (identityKeys), never by bare position. A masked
// value is refused ("re-enter the secret") when it has no stored
// counterpart, when a destination field (destKeys) in its mapping or any
// mapping above it changed, or when its list entry cannot be matched
// unambiguously. A new or changed ${VAR} reference in a field that is not
// secret is refused too.
func MergeMasked(newRaw, oldRaw []byte) ([]byte, error) {
	nr, err := parseDoc(newRaw)
	if err != nil {
		return nil, err
	}
	or, err := parseDoc(oldRaw)
	if err != nil {
		return nil, errors.New("the current config file is not valid YAML")
	}
	if err := (merger{}).merge(nr, or, nil, false, "", false); err != nil {
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
