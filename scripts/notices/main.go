// Command notices generates THIRD_PARTY_NOTICES.md: the licenses of every
// module compiled into the doorwarden binary (linux/amd64 and linux/arm64,
// CGO disabled, the same settings as the release image).
//
//	go run ./scripts/notices          # rewrite THIRD_PARTY_NOTICES.md
//	go run ./scripts/notices -check   # fail if the file is stale or a license is unrecognized
//
// The module list comes from `go list -deps`, so modules that are only used
// by tests or tools are not included. License texts are read from the
// module cache (`.Module.Dir`); no absolute path is written to the output.
// A license is recognized by distinctive phrases of its text. A module whose
// main license file is missing or not recognized is an error: add the
// license to classify (or an entry to overrides after reading the text).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const outFile = "THIRD_PARTY_NOTICES.md"

// platforms are the release image targets (see .github/workflows/release.yml).
var platforms = []string{"linux/amd64", "linux/arm64"}

// overrides fixes the license expression of a module whose license file
// holds several licenses that the phrase classifier cannot order. Keys are
// module paths. Every entry must be checked against the file by hand.
var overrides = map[string]string{
	// LICENSE.txt: "dual-licensed ... UPL 1.0 ... or Apache License 2.0 ... You may choose either license."
	"github.com/nrdcg/oci-go-sdk/common/v1065": "UPL-1.0 OR Apache-2.0",
	"github.com/nrdcg/oci-go-sdk/dns/v1065":    "UPL-1.0 OR Apache-2.0",
}

// Module is one third-party module linked into the binary.
type Module struct {
	Path    string
	Version string
	Dir     string
	License string // SPDX-style identifier(s) of the main license file(s)
	Main    []file // main license files (classified)
	Extra   []file // additional license / NOTICE files (reproduced verbatim)
}

type file struct {
	Name string
	Text string
}

var (
	mainLicense  = regexp.MustCompile(`(?i)^(licen[cs]e|copying|unlicense)(\.(txt|md|mit|rst))?$`)
	extraLicense = regexp.MustCompile(`(?i)^((licen[cs]e|copying)[-._].+|notice(\.(txt|md))?)$`)
)

func main() {
	check := flag.Bool("check", false, "verify "+outFile+" is up to date and every license is recognized")
	flag.Parse()
	out, err := generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
	if *check {
		cur, err := os.ReadFile(outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "notices:", err)
			os.Exit(1)
		}
		if !bytes.Equal(cur, out) {
			fmt.Fprintf(os.Stderr, "notices: %s is stale; run `make notices` (go run ./scripts/notices) and commit the result\n", outFile)
			os.Exit(1)
		}
		fmt.Println("notices: " + outFile + " is up to date")
		return
	}
	if err := os.WriteFile(outFile, out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func generate() ([]byte, error) {
	mods, err := listModules()
	if err != nil {
		return nil, err
	}
	var problems []string
	for i := range mods {
		if err := loadLicenses(&mods[i]); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return nil, errors.New("unrecognized licenses:\n  " + strings.Join(problems, "\n  "))
	}
	goLicense, err := goStdLicense()
	if err != nil {
		return nil, err
	}
	return render(mods, goLicense), nil
}

func listModules() ([]Module, error) {
	seen := map[string]Module{}
	for _, p := range platforms {
		goos, goarch, _ := strings.Cut(p, "/")
		cmd := exec.Command("go", "list", "-deps", "-f",
			"{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{with .Replace}}\t{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}{{end}}",
			"./cmd/doorwarden")
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		cmd.Stderr = os.Stderr
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list (%s): %w", p, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" {
				continue
			}
			f := strings.Split(line, "\t")
			m := Module{Path: f[0], Version: f[1], Dir: f[2]}
			if len(f) == 6 { // replaced module: licenses come from the replacement
				m.Version, m.Dir = f[4], f[5]
			}
			if m.Dir == "" {
				return nil, fmt.Errorf("module %s has no directory; run `go mod download`", m.Path)
			}
			seen[m.Path] = m
		}
	}
	mods := make([]Module, 0, len(seen))
	for _, m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

func loadLicenses(m *Module) error {
	ents, err := os.ReadDir(m.Dir)
	if err != nil {
		return fmt.Errorf("%s: %v", m.Path, err)
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		isMain := mainLicense.MatchString(name)
		if !isMain && !extraLicense.MatchString(name) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.Dir, name))
		if err != nil {
			return fmt.Errorf("%s: %v", m.Path, err)
		}
		f := file{Name: name, Text: strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n\t ")}
		if isMain {
			m.Main = append(m.Main, f)
		} else {
			m.Extra = append(m.Extra, f)
		}
	}
	if len(m.Main) == 0 {
		return fmt.Errorf("%s %s: no LICENSE file found", m.Path, m.Version)
	}
	if o, ok := overrides[m.Path]; ok {
		m.License = o
		return nil
	}
	var ids []string
	for _, f := range m.Main {
		got := classify(f.Text)
		if len(got) == 0 {
			return fmt.Errorf("%s %s: %s: license text not recognized", m.Path, m.Version, f.Name)
		}
		ids = appendUnique(ids, got...)
	}
	m.License = strings.Join(ids, " AND ")
	return nil
}

func appendUnique(s []string, v ...string) []string {
	for _, x := range v {
		dup := false
		for _, y := range s {
			dup = dup || x == y
		}
		if !dup {
			s = append(s, x)
		}
	}
	return s
}

var spaces = regexp.MustCompile(`[\s*#>/]+`)

func normalize(s string) string {
	return strings.TrimSpace(spaces.ReplaceAllString(strings.ToLower(s), " "))
}

// classify returns the licenses whose distinctive wording appears in text,
// in a fixed order. An empty result means the text is not recognized.
func classify(text string) []string {
	t := normalize(text)
	has := func(phrases ...string) bool {
		for _, p := range phrases {
			if !strings.Contains(t, p) {
				return false
			}
		}
		return true
	}
	var ids []string
	if has("apache license", "version 2.0") {
		ids = append(ids, "Apache-2.0")
	}
	if has("mozilla public license", "version 2.0") {
		ids = append(ids, "MPL-2.0")
	}
	if has("redistribution and use in source and binary forms") {
		switch {
		case has("neither the name") || has("names of its contributors may") || has("name of the copyright holder nor"):
			ids = append(ids, "BSD-3-Clause")
		default:
			ids = append(ids, "BSD-2-Clause")
		}
	}
	if has("permission is hereby granted, free of charge, to any person obtaining a copy") {
		ids = append(ids, "MIT")
	}
	if has("permission to use, copy, modify, and") && has("distribute this software for any purpose with or without fee is hereby granted") {
		ids = append(ids, "ISC")
	}
	if has("this is free and unencumbered software released into the public domain") {
		ids = append(ids, "Unlicense")
	}
	if has("universal permissive license") {
		ids = append(ids, "UPL-1.0")
	}
	if has("creative commons", "cc0") {
		ids = append(ids, "CC0-1.0")
	}
	return ids
}

func goStdLicense() (string, error) {
	b, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOROOT: %w", err)
	}
	root := strings.TrimSpace(string(b))
	// Some packaged toolchains (Homebrew) keep LICENSE one level above GOROOT.
	lic, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if errors.Is(err, os.ErrNotExist) {
		lic, err = os.ReadFile(filepath.Join(root, "..", "LICENSE"))
	}
	if err != nil {
		return "", fmt.Errorf("Go standard library LICENSE: %w", err)
	}
	text := strings.TrimRight(strings.ReplaceAll(string(lic), "\r\n", "\n"), "\n\t ")
	if got := classify(text); len(got) != 1 || got[0] != "BSD-3-Clause" {
		return "", fmt.Errorf("Go standard library LICENSE not recognized as BSD-3-Clause (%v)", got)
	}
	return text, nil
}

func render(mods []Module, goLicense string) []byte {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# Third-party notices\n\n")
	w("<!-- Generated by `go run ./scripts/notices` (make notices). Do not edit by hand. -->\n\n")
	w("Doorwarden is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).\n")
	w("The `doorwarden` binary also contains the Go standard library and the %d third-party\n", len(mods))
	w("Go modules listed below: every module that `go list -deps ./cmd/doorwarden` reports for\n")
	w("%s with `CGO_ENABLED=0`. Modules used only by tests or tooling are not\n", strings.Join(platforms, " and "))
	w("listed. The container image's base layer (distroless) carries its own notices.\n\n")

	counts := map[string]int{}
	for _, m := range mods {
		counts[m.License]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w("## Summary\n\n| License | Modules |\n|---|---|\n")
	for _, k := range keys {
		w("| %s | %d |\n", k, counts[k])
	}
	w("\n")

	w("## MPL-2.0 modules\n\n")
	w("These modules are under the Mozilla Public License 2.0, a file-level copyleft\n")
	w("license. Doorwarden uses them unmodified. Their source code is available at the\n")
	w("links below (the exact versions linked into the binary):\n\n")
	n := 0
	for _, m := range mods {
		if strings.Contains(m.License, "MPL-2.0") {
			n++
			w("- `%s` %s: <https://pkg.go.dev/%s@%s> (source archive: <https://proxy.golang.org/%s/@v/%s.zip>)\n",
				m.Path, m.Version, m.Path, m.Version, escapePath(m.Path), m.Version)
		}
	}
	if n == 0 {
		w("None.\n")
	}
	w("\n")

	w("## Modules\n\n| Module | Version | License | Files |\n|---|---|---|---|\n")
	for _, m := range mods {
		var names []string
		for _, f := range append(append([]file{}, m.Main...), m.Extra...) {
			names = append(names, f.Name)
		}
		w("| `%s` | %s | %s | %s |\n", m.Path, m.Version, m.License, strings.Join(names, ", "))
	}
	w("\n")

	// License texts, deduplicated by exact content.
	type text struct {
		hash  string
		body  string
		users []string
	}
	byHash := map[string]*text{}
	var order []*text
	add := func(user, body string) {
		sum := sha256.Sum256([]byte(body))
		h := hex.EncodeToString(sum[:8])
		t, ok := byHash[h]
		if !ok {
			t = &text{hash: h, body: body}
			byHash[h] = t
			order = append(order, t)
		}
		t.users = append(t.users, user)
	}
	add("Go standard library (LICENSE)", goLicense)
	for _, m := range mods {
		for _, f := range append(append([]file{}, m.Main...), m.Extra...) {
			add(fmt.Sprintf("`%s` %s (%s)", m.Path, m.Version, f.Name), f.Text)
		}
	}
	w("## License and notice texts\n\n")
	w("Each distinct text appears once, followed by the modules whose file has exactly that text.\n\n")
	fence := "````````"
	for i, t := range order {
		w("### Text %d\n\nUsed by:\n\n", i+1)
		for _, u := range t.users {
			w("- %s\n", u)
		}
		w("\n%s text\n%s\n%s\n\n", fence, t.body, fence)
	}
	return []byte(strings.TrimRight(b.String(), "\n") + "\n")
}

// escapePath applies the module proxy's case encoding ("!" + lower case).
func escapePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
