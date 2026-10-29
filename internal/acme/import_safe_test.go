package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// npmTree is <tmp>/letsencrypt/{live,archive} with live/npm-N/*.pem
// symlinked to archive/npm-N/*1.pem, the layout certbot and NPM use.
func npmTree(t *testing.T, h *harness, n string, names []string) (root, live string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "letsencrypt")
	live = filepath.Join(root, "live")
	arch := filepath.Join(root, "archive", n)
	must(t, os.MkdirAll(arch, 0o700))
	must(t, os.MkdirAll(filepath.Join(live, n), 0o700))
	chain, key := h.ca.ca.leaf(t, names, t0.Add(50*24*time.Hour))
	must(t, os.WriteFile(filepath.Join(arch, "fullchain1.pem"), chain, 0o600))
	must(t, os.WriteFile(filepath.Join(arch, "privkey1.pem"), key, 0o600))
	must(t, os.Symlink(filepath.Join("..", "..", "archive", n, "fullchain1.pem"), filepath.Join(live, n, FullchainFile)))
	must(t, os.Symlink(filepath.Join("..", "..", "archive", n, "privkey1.pem"), filepath.Join(live, n, PrivkeyFile)))
	return root, live
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestImportNPMLiveToArchiveSymlinksWork(t *testing.T) {
	h := newHarness(t, nil, nil)
	_, live := npmTree(t, h, "npm-1", []string{"a.example.test"})
	for _, d := range []string{live, filepath.Join(live, "npm-1")} {
		res, err := h.m.ImportNPMDir(ctx, d)
		if err != nil || len(res) != 1 || res[0].Err != nil {
			t.Fatalf("%s: %+v %v", d, res, err)
		}
	}
}

func TestImportNPMSymlinkedCertDir(t *testing.T) {
	h := newHarness(t, nil, nil)
	root, live := npmTree(t, h, "npm-1", []string{"a.example.test"})
	// live/npm-2 is itself a symlink to a directory inside the tree.
	real := filepath.Join(root, "store", "npm-2")
	must(t, os.MkdirAll(real, 0o700))
	chain, key := h.ca.ca.leaf(t, []string{"b.example.test"}, t0.Add(50*24*time.Hour))
	must(t, os.WriteFile(filepath.Join(real, FullchainFile), chain, 0o600))
	must(t, os.WriteFile(filepath.Join(real, PrivkeyFile), key, 0o600))
	must(t, os.Symlink(filepath.Join("..", "store", "npm-2"), filepath.Join(live, "npm-2")))
	res, err := h.m.ImportNPMDir(ctx, live)
	if err != nil || len(res) != 2 || res[0].Err != nil || res[1].Err != nil {
		t.Fatalf("%+v %v", res, err)
	}
	// The live dir given through a symlink works as well.
	alias := filepath.Join(t.TempDir(), "le-live")
	must(t, os.Symlink(live, alias))
	if res, err := h.m.ImportNPMDir(ctx, alias); err != nil || len(res) != 2 || res[1].Err != nil {
		t.Fatalf("via alias: %+v %v", res, err)
	}
}

func TestImportNPMRejectsUnsafeFiles(t *testing.T) {
	h := newHarness(t, nil, nil)
	check := func(name string, setup func(dir string), want string) {
		t.Helper()
		_, live := npmTree(t, h, "npm-1", []string{"a.example.test"})
		dir := filepath.Join(live, "npm-1")
		must(t, os.Remove(filepath.Join(dir, FullchainFile)))
		setup(dir)
		done := make(chan []ImportResult, 1)
		go func() {
			res, _ := h.m.ImportNPMDir(ctx, live)
			done <- res
		}()
		select {
		case res := <-done:
			if len(res) != 1 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), want) {
				t.Errorf("%s: want %q, got %+v", name, want, res)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: import hung", name)
		}
	}
	check("dev-zero", func(dir string) {
		must(t, os.Symlink("/dev/zero", filepath.Join(dir, FullchainFile)))
	}, "outside")
	check("outside-tree", func(dir string) {
		other := filepath.Join(t.TempDir(), "x.pem")
		chain, _ := h.ca.ca.leaf(t, []string{"a.example.test"}, t0.Add(50*24*time.Hour))
		must(t, os.WriteFile(other, chain, 0o600))
		must(t, os.Symlink(other, filepath.Join(dir, FullchainFile)))
	}, "outside")
	check("huge", func(dir string) {
		must(t, os.WriteFile(filepath.Join(dir, FullchainFile), bytes.Repeat([]byte("A"), maxPEMSize+1), 0o600))
	}, "larger than")
	check("directory", func(dir string) {
		must(t, os.Mkdir(filepath.Join(dir, FullchainFile), 0o700))
	}, "not a regular file")
	if p, err := exec.LookPath("mkfifo"); err == nil {
		check("fifo", func(dir string) {
			must(t, exec.Command(p, filepath.Join(dir, FullchainFile)).Run())
		}, "not a regular file")
	} else {
		t.Log("mkfifo not available; FIFO case skipped")
	}
}

func TestImportPEMSizeBound(t *testing.T) {
	h := newHarness(t, nil, nil)
	chain, key := h.ca.ca.leaf(t, []string{"a.example.test"}, t0.Add(50*24*time.Hour))
	big := append(append([]byte(nil), chain...), bytes.Repeat([]byte("\n"), maxPEMSize)...)
	if _, err := h.m.ImportPEM(ctx, "example.test", big, key); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("%v", err)
	}
	if _, err := h.m.ImportPEM(ctx, "example.test", chain, append(append([]byte(nil), key...), bytes.Repeat([]byte(" "), maxPEMSize)...)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("%v", err)
	}
}

// selfLeaf builds a leaf for names signed by a fresh intermediate, with the
// given key type, and returns leaf DER, intermediate DER and key.
func keyedLeaf(t *testing.T, h *harness, priv any, names []string) (leafDER, interDER []byte) {
	t.Helper()
	var pub any
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(50 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, h.ca.ca.cert, pub, h.ca.ca.key)
	must(t, err)
	return der, h.ca.ca.cert.Raw
}

func pemOf(typ string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }

func TestImportReencodesKeyTypes(t *testing.T) {
	h := newHarness(t, nil, nil)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ec)
	edDER, _ := x509.MarshalPKCS8PrivateKey(ed)
	for i, tc := range []struct {
		name string
		priv any
		key  []byte
	}{
		{"ecdsa-sec1", ec, pemOf("EC PRIVATE KEY", ecDER)},
		{"rsa-pkcs1", rk, pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk))},
		{"ed25519-pkcs8", ed, pemOf("PRIVATE KEY", edDER)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, inter := keyedLeaf(t, h, tc.priv, []string{fmtS("k%d.example.test", i)})
			chain := append(pemOf("CERTIFICATE", leaf), pemOf("CERTIFICATE", inter)...)
			// Comments around blocks are fine; they are not stored.
			chain = append([]byte("subject=whatever\n"), chain...)
			ir, err := h.m.ImportPEM(ctx, "example.test", chain, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			kb, _ := os.ReadFile(filepath.Join(h.dir, ir.Bundle.Dir, PrivkeyFile))
			blk, rest := pem.Decode(kb)
			if blk == nil || blk.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
				t.Fatalf("stored key is not a single PKCS#8 block: %q", blk.Type)
			}
			if _, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
				t.Fatal(err)
			}
			cb, _ := os.ReadFile(filepath.Join(h.dir, ir.Bundle.Dir, FullchainFile))
			if !bytes.Equal(cb, append(pemOf("CERTIFICATE", leaf), pemOf("CERTIFICATE", inter)...)) {
				t.Fatal("stored chain is not the re-encoded certificates")
			}
		})
	}
}

func TestImportRejectsMalformedPEM(t *testing.T) {
	h := newHarness(t, nil, nil)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ec)
	key := pemOf("EC PRIVATE KEY", ecDER)
	leaf, inter := keyedLeaf(t, h, ec, []string{"m.example.test"})
	chain := append(pemOf("CERTIFICATE", leaf), pemOf("CERTIFICATE", inter)...)
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}, Bytes: ecDER})
	for _, tc := range []struct {
		name       string
		chain, key []byte
		want       string
	}{
		{"reversed chain", append(pemOf("CERTIFICATE", inter), pemOf("CERTIFICATE", leaf)...), key, "chain order"},
		{"trailing junk chain", append(append([]byte(nil), chain...), "junk"...), key, "trailing data"},
		{"unknown block in chain", append(append([]byte(nil), chain...), pemOf("X509 CRL", []byte{1})...), key, "unexpected PEM block"},
		{"trailing junk key", chain, append(append([]byte(nil), key...), "junk"...), "trailing data"},
		{"two keys", chain, append(append([]byte(nil), key...), key...), "exactly one private key"},
		{"encrypted key (legacy)", chain, encrypted, "encrypted"},
		{"encrypted key (pkcs8)", chain, pemOf("ENCRYPTED PRIVATE KEY", []byte{1, 2, 3}), "encrypted"},
		{"cert in key file", chain, pemOf("CERTIFICATE", leaf), "exactly one private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.m.ImportPEM(ctx, "example.test", tc.chain, tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), keyBody(key)[:20]) {
				t.Fatal("key material in error")
			}
		})
	}
}
