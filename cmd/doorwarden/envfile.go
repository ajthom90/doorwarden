package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ajthom90/doorwarden/internal/config"
)

// maxEnvFileSize bounds an -env-file.
const maxEnvFileSize = 1 << 20

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// parseEnvFile reads KEY=VALUE lines in docker's --env-file format: blank
// lines and lines starting with # are ignored, the value is everything
// after the first = taken literally (no quotes are removed, nothing is
// expanded), a trailing \r is dropped. Errors name the file and line
// number only, never a line's content (it may hold a secret).
func parseEnvFile(path string) (map[string]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("env file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("env file %s is not a regular file", path)
	}
	if fi.Size() > maxEnvFileSize {
		return nil, fmt.Errorf("env file %s is larger than %d bytes", path, maxEnvFileSize)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("env file: %w", err)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), maxEnvFileSize)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSuffix(sc.Text(), "\r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !envNameRe.MatchString(k) {
			return nil, fmt.Errorf("env file %s line %d: expected NAME=VALUE", path, n)
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, errors.New("a line is too long"))
	}
	return out, nil
}

var cliEnvRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)`)

// cliConfig loads a doorwarden config for an offline CLI (import-npm,
// certs import-npm). Variables come from the process environment, then
// from envFile (-env-file; docker semantics: the process environment wins).
// Variables set in neither expand to "" instead of failing the load: these
// commands need only the zones (and the certificate directory), not the
// credentials a production config typically keeps in variables. The names
// of such variables are returned so the caller can say so. An unquoted
// ${VAR} in a number or boolean field cannot decode from "" and still
// fails (with a hint). Errors never contain variable values.
func cliConfig(path, envFile string) (*config.Config, []string, error) {
	file := map[string]string{}
	if envFile != "" {
		f, err := parseEnvFile(envFile)
		if err != nil {
			return nil, nil, err
		}
		file = f
	}
	lookup := func(k string) (string, bool) {
		if v, ok := os.LookupEnv(k); ok {
			return v, true
		}
		v, ok := file[k]
		return v, ok
	}
	unset := map[string]bool{}
	tolerant := func(k string) (string, bool) {
		if v, ok := lookup(k); ok {
			return v, true
		}
		unset[k] = true
		return "", true
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := config.Parse(raw, tolerant)
	names := make([]string, 0, len(unset))
	for k := range unset {
		names = append(names, k)
	}
	sort.Strings(names)
	if err != nil {
		msg := scrubValues(err.Error(), raw, lookup)
		if len(names) > 0 {
			msg += fmt.Sprintf(" (unset variable(s) %s expanded to empty; pass -env-file or set them)", strings.Join(names, ", "))
		}
		return nil, names, fmt.Errorf("config %s: %s", path, msg)
	}
	return cfg, names, nil
}

// yamlQuotedRe matches the (possibly truncated) values the YAML decoder
// quotes in unmarshal errors.
var yamlQuotedRe = regexp.MustCompile("`[^`]*`")

// scrubValues replaces in msg the values of every variable raw references
// and every value the YAML decoder quoted (it may be a truncated variable
// value, which a plain replacement would miss).
func scrubValues(msg string, raw []byte, lookup func(string) (string, bool)) string {
	msg = yamlQuotedRe.ReplaceAllString(msg, "`[value]`")
	for _, m := range cliEnvRefRe.FindAllSubmatch(raw, -1) {
		if v, ok := lookup(string(m[1])); ok && len(v) >= 3 {
			msg = strings.ReplaceAll(msg, v, "[redacted]")
		}
	}
	return msg
}
