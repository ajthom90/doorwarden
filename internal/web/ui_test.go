package web

import (
	"bytes"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/net/html"
)

func TestUIStaticServedWithTypesAndHeaders(t *testing.T) {
	e := newTestEnv(t)
	c := e.anon()
	want := map[string]string{
		"/":                "text/html; charset=utf-8",
		"/index.html":      "text/html; charset=utf-8",
		"/app.css":         "text/css; charset=utf-8",
		"/theme.js":        "text/javascript; charset=utf-8",
		"/js/app.js":       "text/javascript; charset=utf-8",
		"/js/dom.js":       "text/javascript; charset=utf-8",
		"/favicon.svg":     "image/svg+xml",
		"/js/views/dns.js": "text/javascript; charset=utf-8",
	}
	for p, ct := range want {
		w := c.do("GET", p, nil)
		if w.Code != 200 {
			t.Fatalf("GET %s: %d", p, w.Code)
		}
		h := w.Header()
		if got := h.Get("Content-Type"); got != ct {
			t.Errorf("GET %s: Content-Type %q, want %q", p, got, ct)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s: no nosniff", p)
		}
		if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") {
			t.Errorf("GET %s: CSP %q", p, h.Get("Content-Security-Policy"))
		}
		if h.Get("Cache-Control") != "no-cache" {
			t.Errorf("GET %s: Cache-Control %q", p, h.Get("Cache-Control"))
		}
		etag := h.Get("ETag")
		if !regexp.MustCompile(`^"[0-9a-f]{24}"$`).MatchString(etag) {
			t.Errorf("GET %s: ETag %q", p, etag)
		}
		f := staticTable[p]
		if !bytes.Equal(w.Body.Bytes(), f.body) {
			t.Errorf("GET %s: body differs from the embedded file", p)
		}

		// revalidation answers 304 with no body
		w = c.do("GET", p, nil, withHeader("If-None-Match", etag))
		if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
			t.Errorf("GET %s If-None-Match: %d, %d bytes", p, w.Code, w.Body.Len())
		}

		// HEAD: headers, no body
		w = c.do("HEAD", p, nil)
		if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Type") != ct {
			t.Errorf("HEAD %s: %d, %d bytes, %q", p, w.Code, w.Body.Len(), w.Header().Get("Content-Type"))
		}
	}
	if !bytes.Equal(staticTable["/"].body, staticTable["/index.html"].body) {
		t.Fatal("/ is not index.html")
	}
}

func TestUIStaticPublicButAPIStillDenied(t *testing.T) {
	e := newTestEnv(t)
	c := e.anon()
	for p := range staticTable {
		if w := c.do("GET", p, nil); w.Code != 200 {
			t.Errorf("anonymous GET %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/api/v1/services", "/api/v1/config", "/api/v1/events", "/api/v1/activity", "/metrics"} {
		if w := c.do("GET", p, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous GET %s: %d, want 401", p, w.Code)
		}
	}
	// static paths are public only for safe methods: anything else is
	// denied before routing, signed in or not
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if w := c.do(m, "/index.html", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s /index.html: %d, want 401", m, w.Code)
		}
	}
	admin := e.setupAdmin()
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		w := admin.do(m, "/js/app.js", "{}")
		if w.Code < 400 || bytes.Contains(w.Body.Bytes(), []byte("import")) {
			t.Errorf("admin %s /js/app.js: %d %q", m, w.Code, w.Body.String())
		}
	}
	// paths that are not files are not served, and there is no listing
	for _, p := range []string{"/js/", "/js", "/js/views/", "/ui/index.html", "/index.htm", "/nope.js", "/app.css/"} {
		w := admin.do("GET", p, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("admin GET %s: %d, want 404", p, w.Code)
		}
	}
}

// Traversal and encoding tricks never reach a file. Anonymous requests are
// refused by the auth middleware (401: an escaped path is never public);
// signed-in ones find no route (404) or are cleaned (400/301 by the mux,
// never to a file outside the table).
func TestUIStaticTraversal(t *testing.T) {
	e := newTestEnv(t)
	anon := e.anon()
	admin := e.setupAdmin()
	paths := []string{
		"/..%2fapi/v1/services",
		"/js/..%2findex.html",
		"/js/%2e%2e/index.html",
		"/%2e%2e/%2e%2e/etc/passwd",
		"/js/%252e%252e/index.html",
		"/..%252fui.go",
		"/js%2fapp.js",
		"/js\\..\\index.html",
		"/js/..\\..\\ui.go",
		"/%5c..%5cui.go",
		"/ui.go",
		"/ui/index.html",
		"/index.html%00.js",
	}
	secret := []byte("package web")
	for _, p := range paths {
		for name, c := range map[string]*client{"anon": anon, "admin": admin} {
			w := c.do("GET", p, nil)
			switch w.Code {
			case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusMovedPermanently:
			default:
				t.Errorf("%s GET %s: %d", name, p, w.Code)
			}
			b := w.Body.Bytes()
			if bytes.Contains(b, secret) || bytes.Contains(b, []byte("<!doctype")) || bytes.Contains(b, []byte("import ")) {
				t.Errorf("%s GET %s: served file content", name, p)
			}
			if name == "anon" && w.Code == http.StatusMovedPermanently {
				t.Errorf("anon GET %s: redirected before auth", p)
			}
		}
	}
}

func TestUIIndexHasNoInlineCode(t *testing.T) {
	e := newTestEnv(t)
	w := e.anon().do("GET", "/", nil)
	csp := w.Header().Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP %q lacks %q", csp, d)
		}
	}
	if strings.Contains(csp, "unsafe-") {
		t.Errorf("CSP allows unsafe sources: %q", csp)
	}
	for p, f := range staticTable {
		if !strings.HasSuffix(p, ".html") {
			continue
		}
		doc, err := html.Parse(bytes.NewReader(f.body))
		if err != nil {
			t.Fatal(err)
		}
		scripts := 0
		var walk func(n *html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode {
				switch n.Data {
				case "script":
					scripts++
					src := attr(n, "src")
					if src == "" || !strings.HasPrefix(src, "/") || strings.HasPrefix(src, "//") {
						t.Errorf("%s: script without a same-origin src: %q", p, src)
					}
					if n.FirstChild != nil && strings.TrimSpace(n.FirstChild.Data) != "" {
						t.Errorf("%s: inline script body", p)
					}
					if staticTable[src] == nil {
						t.Errorf("%s: script %s is not an embedded file", p, src)
					}
				case "style":
					t.Errorf("%s: inline <style>", p)
				case "link":
					if href := attr(n, "href"); staticTable[href] == nil {
						t.Errorf("%s: link to %q, not an embedded file", p, href)
					}
				}
				for _, a := range n.Attr {
					k := strings.ToLower(a.Key)
					if k == "style" || strings.HasPrefix(k, "on") {
						t.Errorf("%s: <%s %s=...> is inline code", p, n.Data, a.Key)
					}
					if strings.Contains(strings.ToLower(a.Val), "javascript:") {
						t.Errorf("%s: javascript: URL in <%s %s>", p, n.Data, a.Key)
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)
		if scripts == 0 {
			t.Errorf("%s: no scripts at all", p)
		}
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// The UI builds the DOM only with createElement/textContent (dom.js), so
// server data can never become markup. This lint fails on any HTML-string
// sink or dynamic code in the shipped JavaScript.
func TestUIJavaScriptLint(t *testing.T) {
	forbidden := []struct {
		re  *regexp.Regexp
		why string
	}{
		{regexp.MustCompile(`\binnerHTML\b`), "innerHTML"},
		{regexp.MustCompile(`\bouterHTML\b`), "outerHTML"},
		{regexp.MustCompile(`\binsertAdjacentHTML\b`), "insertAdjacentHTML"},
		{regexp.MustCompile(`\bcreateContextualFragment\b`), "createContextualFragment"},
		{regexp.MustCompile(`\bDOMParser\b`), "DOMParser"},
		{regexp.MustCompile(`document\s*\.\s*write(ln)?\b`), "document.write"},
		{regexp.MustCompile(`\beval\s*\(`), "eval"},
		{regexp.MustCompile(`\bnew\s+Function\b`), "new Function"},
		{regexp.MustCompile(`\bFunction\s*\(`), "Function()"},
		{regexp.MustCompile(`\bset(Timeout|Interval)\s*\(\s*["'` + "`" + `]`), "setTimeout/setInterval with a string"},
		{regexp.MustCompile(`setAttribute\s*\(\s*["']\s*(style|on\w+|srcdoc)\b`), "setAttribute of style/on*/srcdoc"},
		{regexp.MustCompile(`(?i)javascript:`), "javascript: URL"},
		{regexp.MustCompile(`\.style\s*\.\s*cssText|\.style\s*=`), "inline style"},
		{regexp.MustCompile(`\bimport\s*\(`), "dynamic import"},
		// code and data load only from this origin (links out to a
		// published service's host are fine)
		{regexp.MustCompile(`\b(from|import|fetch\s*\(|EventSource\s*\(|WebSocket\s*\()\s*["'` + "`" + `]\s*(https?:|wss?:)?//`), "cross-origin code or data"},
	}
	n := 0
	err := fs.WalkDir(uiFiles, "ui", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") {
			return err
		}
		n++
		b, err := fs.ReadFile(uiFiles, p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := stripLineComment(line)
			for _, f := range forbidden {
				if f.re.MatchString(code) {
					t.Errorf("%s:%d: %s: %s", p, i+1, f.why, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Fatalf("lint saw only %d .js files", n)
	}
}

// stripLineComment skips lines that are only a comment, so prose about a
// pattern (e.g. "never innerHTML") does not trip the lint. Any line with
// code on it is linted whole, trailing comment included.
func stripLineComment(line string) string {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
		return ""
	}
	return line
}

func TestUILoadStaticRejectsUnknownTypes(t *testing.T) {
	fsys := fstest.MapFS{
		"ui/index.html": {Data: []byte("<!doctype html>")},
		"ui/x.wasm":     {Data: []byte{0}},
	}
	if _, err := loadStatic(fsys, "ui"); err == nil {
		t.Fatal("an unknown extension was accepted")
	}
	if _, err := loadStatic(fstest.MapFS{"ui/a.js": {Data: []byte("x")}}, "ui"); err == nil {
		t.Fatal("a UI without index.html was accepted")
	}
	tb, err := loadStatic(fstest.MapFS{"ui/index.html": {Data: []byte("a")}, "ui/js/b.js": {Data: []byte("b")}}, "ui")
	if err != nil {
		t.Fatal(err)
	}
	if tb["/js/b.js"] == nil || tb["/"] != tb["/index.html"] || len(tb) != 3 {
		t.Fatalf("table: %v", tb)
	}
}
