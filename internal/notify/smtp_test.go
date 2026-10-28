package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

// fakeSMTP is a minimal SMTP server over implicit TLS (or plain).
type fakeSMTP struct {
	ln    net.Listener
	cert  tls.Certificate
	pool  *x509.CertPool
	mu    sync.Mutex
	msgs  []fakeMsg
	auth  string // raw AUTH line seen
	wg    sync.WaitGroup
	plain bool
	// authFail makes AUTH answer 535 echoing the credentials (hostile server).
	authFail bool
}

type fakeMsg struct {
	from string
	to   []string
	data string
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func startFakeSMTP(t *testing.T, plain bool) *fakeSMTP {
	t.Helper()
	f := &fakeSMTP{plain: plain}
	f.cert, f.pool = selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if !plain {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	}
	f.ln = ln
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() { defer f.wg.Done(); f.serve(c) }()
		}
	}()
	t.Cleanup(func() { ln.Close(); f.wg.Wait() })
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	w := func(s string) { fmt.Fprintf(c, "%s\r\n", s) }
	w("220 fake ESMTP")
	var cur fakeMsg
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			fmt.Fprintf(c, "250-fake\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n")
		case strings.HasPrefix(up, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = line
			f.mu.Unlock()
			if f.authFail {
				raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				w("535 rejected " + strings.ReplaceAll(string(raw), "\x00", " "))
				continue
			}
			w("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			cur = fakeMsg{from: angle(line)}
			w("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			cur.to = append(cur.to, angle(line))
			w("250 ok")
		case up == "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			cur.data = b.String()
			f.mu.Lock()
			f.msgs = append(f.msgs, cur)
			f.mu.Unlock()
			w("250 queued")
		case up == "QUIT":
			w("221 bye")
			return
		case up == "RSET" || up == "NOOP":
			w("250 ok")
		default:
			w("502 unsupported")
		}
	}
}

func (f *fakeSMTP) messages() []fakeMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMsg(nil), f.msgs...)
}

func smtpCfg(f *fakeSMTP) config.SMTPCfg {
	return config.SMTPCfg{
		NotifyCommon: config.NotifyCommon{Name: "mail"},
		Host:         "127.0.0.1", Port: f.port(), TLS: "tls",
		Username: "mailuser", Password: "PASSWORD-SENTINEL",
		From: "Doorwarden <doorwarden@example.test>",
		To:   []string{"admin@example.test", "ops@example.test"},
	}
}

func newTestSMTP(t *testing.T, cfg config.SMTPCfg, f *fakeSMTP) *SMTP {
	t.Helper()
	s, err := NewSMTP(cfg, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s.tlsConfig = &tls.Config{RootCAs: f.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	return s
}

func TestSMTPSendsRFC822(t *testing.T) {
	f := startFakeSMTP(t, false)
	cfg := smtpCfg(f)
	s := newTestSMTP(t, cfg, f)
	// ServerName for PLAIN auth must equal host given to client.
	e := testEvent
	e.Subject = "Renewal failed – zertifikat läuft ab"
	e.Message = "line1\n.dot line\nlast"
	if err := s.Send(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	msgs := f.messages()
	if len(msgs) != 1 {
		t.Fatalf("msgs %d", len(msgs))
	}
	m := msgs[0]
	if m.from != "doorwarden@example.test" || len(m.to) != 2 || m.to[1] != "ops@example.test" {
		t.Fatalf("envelope %+v", m)
	}
	pm, err := mail.ReadMessage(strings.NewReader(m.data))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, m.data)
	}
	dec := new(mime.WordDecoder)
	subj, err := dec.DecodeHeader(pm.Header.Get("Subject"))
	if err != nil || subj != "[doorwarden] critical Renewal failed – zertifikat läuft ab" {
		t.Fatalf("subject %q (%v) raw %q", subj, err, pm.Header.Get("Subject"))
	}
	if strings.ContainsAny(pm.Header.Get("Subject"), "äö–") {
		t.Fatal("subject not RFC 2047 encoded")
	}
	for _, h := range []string{"From", "To", "Date", "Message-Id", "Mime-Version", "Content-Type"} {
		if pm.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	if !strings.HasPrefix(pm.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("ct %q", pm.Header.Get("Content-Type"))
	}
	if !strings.Contains(m.data, "\r\n\r\n") {
		t.Fatal("no CRLF header terminator")
	}
	if want := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00mailuser\x00PASSWORD-SENTINEL")); f.auth != want {
		t.Fatalf("auth line %q", f.auth)
	}
	body := readQP(t, pm)
	for _, w := range []string{"line1", ".dot line", "last", "zone: example.test", "ACME"} {
		if w == "ACME" {
			w = "line1"
		}
		if !strings.Contains(body, w) {
			t.Errorf("body lacks %q: %q", w, body)
		}
	}
}

func readQP(t *testing.T, pm *mail.Message) string {
	t.Helper()
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := pm.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if strings.EqualFold(pm.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
		out, err := decodeQP(b.String())
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	return b.String()
}

func TestSMTPRejectsHeaderInjection(t *testing.T) {
	f := startFakeSMTP(t, false)
	s := newTestSMTP(t, smtpCfg(f), f)
	for _, subj := range []string{"hi\r\nBcc: evil@example.test", "hi\nBcc: evil@example.test", "hi\rX: y"} {
		e := testEvent
		e.Subject = subj
		err := s.Send(context.Background(), e)
		if err == nil || !IsPermanent(err) {
			t.Fatalf("subject %q: err=%v", subj, err)
		}
	}
	if n := len(f.messages()); n != 0 {
		t.Fatalf("%d messages leaked through", n)
	}
}

func TestNewSMTPRejectsInjectedAddresses(t *testing.T) {
	f := startFakeSMTP(t, false)
	for _, mut := range []func(*config.SMTPCfg){
		func(c *config.SMTPCfg) { c.From = "a@example.test\r\nBcc: x@example.test" },
		func(c *config.SMTPCfg) { c.To = []string{"a@example.test\nBcc: x@example.test"} },
		func(c *config.SMTPCfg) { c.To = nil },
		func(c *config.SMTPCfg) { c.From = "nonsense" },
	} {
		c := smtpCfg(f)
		mut(&c)
		if _, err := NewSMTP(c, time.Second); err == nil {
			t.Errorf("accepted %+v", c.To)
		}
	}
}

func TestSMTPTLSVerificationDefaultOn(t *testing.T) {
	f := startFakeSMTP(t, false)
	s, err := NewSMTP(smtpCfg(f), 3*time.Second) // system roots: self-signed must fail
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), testEvent)
	if err == nil {
		t.Fatal("self-signed certificate accepted")
	}
	if strings.Contains(err.Error(), "PASSWORD-SENTINEL") {
		t.Fatalf("leak: %v", err)
	}
	cfg := smtpCfg(f)
	cfg.InsecureSkipVerify = true
	s, _ = NewSMTP(cfg, 3*time.Second)
	if err := s.Send(context.Background(), testEvent); err != nil {
		t.Fatalf("insecure_skip_verify: %v", err)
	}
}

func TestSMTPNoTLSLoopbackNoAuth(t *testing.T) {
	f := startFakeSMTP(t, true)
	cfg := smtpCfg(f)
	cfg.TLS, cfg.Username, cfg.Password = "none", "", ""
	s, err := NewSMTP(cfg, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testEvent); err != nil {
		t.Fatal(err)
	}
	if len(f.messages()) != 1 || f.auth != "" {
		t.Fatalf("msgs=%d auth=%q", len(f.messages()), f.auth)
	}
}

func TestSMTPRefusesCredentialsWithoutTLSRemote(t *testing.T) {
	cfg := config.SMTPCfg{NotifyCommon: config.NotifyCommon{Name: "m"}, Host: "mail.example.test", Port: 25, TLS: "none",
		Username: "u", Password: "p", From: "a@example.test", To: []string{"b@example.test"}}
	if _, err := NewSMTP(cfg, time.Second); err == nil {
		t.Fatal("accepted plaintext auth to remote host")
	}
}

func TestSMTPConnectError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := config.SMTPCfg{NotifyCommon: config.NotifyCommon{Name: "m"}, Host: "127.0.0.1", Port: port, TLS: "none",
		From: "a@example.test", To: []string{"b@example.test"}}
	s, _ := NewSMTP(cfg, time.Second)
	if err := s.Send(context.Background(), testEvent); err == nil || strings.Contains(err.Error(), strconv.Itoa(port)+"x") {
		t.Fatalf("err = %v", err)
	}
}

func decodeQP(s string) (string, error) {
	b, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(s)))
	return string(b), err
}

func angle(l string) string {
	i, j := strings.IndexByte(l, '<'), strings.IndexByte(l, '>')
	return l[i+1 : j]
}

func TestSMTPAuthFailureDoesNotLeakPassword(t *testing.T) {
	f := startFakeSMTP(t, false)
	f.authFail = true
	s := newTestSMTP(t, smtpCfg(f), f)
	err := s.Send(context.Background(), testEvent)
	if err == nil || !IsPermanent(err) {
		t.Fatalf("err = %v", err)
	}
	// The hostile server echoes the decoded credentials in its 535 reply.
	if strings.Contains(err.Error(), "PASSWORD-SENTINEL") {
		t.Fatalf("leak: %v", err)
	}
}
