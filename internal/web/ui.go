package web

// The web UI: hand-written ES modules, CSS and an index page under ui/,
// embedded at build time and served as exact static files. There is no
// build step and no third-party JavaScript, so `go build` is the whole
// pipeline and the strict CSP (default-src 'self', no inline script or
// style, no eval) holds.
//
// Serving rules:
//   - Every embedded file is registered as its own exact GET pattern (GET
//     also answers HEAD); "/" serves index.html. There is no prefix or
//     fallback handler, so there is no directory listing and nothing a
//     crafted path could reach outside the table built at init.
//   - The auth middleware treats exactly these paths as public, and only
//     for safe methods with an unescaped path (staticPaths). Everything
//     else stays default-deny: a traversal attempt such as /..%2fapi
//     answers 401 before the mux sees it.
//   - Content-Type is set per extension (nosniff is global), the ETag is a
//     content hash and Cache-Control is no-cache, so a browser revalidates
//     every load (304 when unchanged) and an upgrade is picked up at once.
//
// The UI routes in the URL fragment (#/services), so no server path needs
// an SPA fallback.

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed ui
var uiFiles embed.FS

type staticFile struct {
	name  string
	body  []byte
	ctype string
	etag  string
}

// uiTypes maps the extensions the UI may use to their Content-Type. A file
// with any other extension fails loadStatic (and so every test).
var uiTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".svg":  "image/svg+xml",
}

// staticTable maps a URL path to its file; staticPaths is the same key set
// for the auth middleware.
var staticTable, staticPaths = mustLoadStatic()

func mustLoadStatic() (map[string]*staticFile, map[string]bool) {
	t, err := loadStatic(uiFiles, "ui")
	if err != nil {
		panic("web: embedded UI: " + err.Error())
	}
	paths := make(map[string]bool, len(t))
	for p := range t {
		paths[p] = true
	}
	return t, paths
}

func loadStatic(fsys fs.FS, root string) (map[string]*staticFile, error) {
	t := map[string]*staticFile{}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := path.Ext(p)
		ct, ok := uiTypes[ext]
		if !ok {
			return fmt.Errorf("%s: no content type for %q", p, ext)
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		rel := strings.TrimPrefix(p, root)
		t[rel] = &staticFile{name: path.Base(p), body: b, ctype: ct, etag: `"` + hex.EncodeToString(sum[:12]) + `"`}
		return nil
	})
	if err != nil {
		return nil, err
	}
	idx, ok := t["/index.html"]
	if !ok {
		return nil, fmt.Errorf("index.html missing")
	}
	t["/"] = idx
	return t, nil
}

// mountUI registers every static file on mux.
func mountUI(mux *http.ServeMux) {
	for p, f := range staticTable {
		pattern := "GET " + p
		if p == "/" {
			pattern = "GET /{$}"
		}
		mux.Handle(pattern, serveStatic(f))
	}
}

func serveStatic(f *staticFile) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", f.ctype)
		h.Set("ETag", f.etag)
		h.Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, f.name, time.Time{}, bytes.NewReader(f.body))
	})
}
