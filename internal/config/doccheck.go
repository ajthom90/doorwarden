package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

const (
	// maxMappingKeys bounds every mapping: yaml.v3's duplicate-key check
	// is quadratic in a mapping's size, so a huge one is refused before
	// decoding. Real configs have a few dozen keys per mapping.
	maxMappingKeys = 4096
	// maxDocDepth bounds nesting; the schema needs fewer than 10 levels.
	maxDocDepth = 64
	// maxPathLen bounds the key path quoted in an error.
	maxPathLen = 200
)

// CheckDocument refuses document shapes the config never needs and that
// would let a document dodge the loader's checks or cost more than its
// size to decode:
//   - merge keys (<<), checked first: see RejectMergeKeys;
//   - anchors and aliases: an alias could carry a value into another
//     field, and alias expansion (billion laughs) is unbounded work;
//   - mapping keys that are not plain scalars;
//   - mappings with more than maxMappingKeys keys, and nesting deeper
//     than maxDocDepth.
//
// Errors name the key path and line, never a value. The loader
// (config.Parse/Load) and the web config editor both use it.
func CheckDocument(root *yaml.Node) error {
	if err := RejectMergeKeys(root); err != nil {
		return err
	}
	return checkShape(root, nil, 0)
}

func checkShape(n *yaml.Node, path []pathElem, depth int) error {
	if n == nil {
		return nil
	}
	where := func() string {
		w := "the document"
		if len(path) > 0 {
			w = formatPath(path)
			if len(w) > maxPathLen {
				w = w[:maxPathLen] + "..."
			}
		}
		return fmt.Sprintf("%s (line %d)", w, n.Line)
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("%s: YAML anchors and aliases are not supported", where())
	}
	if depth > maxDocDepth {
		return fmt.Errorf("%s: nested more than %d levels", where(), maxDocDepth)
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := checkShape(c, path, depth); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if k := len(n.Content) / 2; k > maxMappingKeys {
			return fmt.Errorf("%s: a mapping with %d keys (at most %d)", where(), k, maxMappingKeys)
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				if k.Kind == yaml.AliasNode || k.Anchor != "" {
					return fmt.Errorf("%s: YAML anchors and aliases are not supported", where())
				}
				return fmt.Errorf("%s: a mapping key must be a plain scalar", where())
			}
			if k.Anchor != "" {
				return fmt.Errorf("%s: YAML anchors and aliases are not supported", where())
			}
			p := append(path[:len(path):len(path)], pathElem{key: k.Value, idx: -1})
			if err := checkShape(n.Content[i+1], p, depth+1); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			if err := checkShape(c, append(path[:len(path):len(path)], pathElem{idx: i}), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
