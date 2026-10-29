package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
)

// SMTP sends events as plain-text mail.
type SMTP struct {
	name    string
	cfg     config.SMTPCfg
	from    *mail.Address
	to      []*mail.Address
	timeout time.Duration
	// tlsConfig overrides the TLS settings (tests inject a trust pool).
	tlsConfig *tls.Config
}

// NewSMTP validates cfg and builds the sender. Addresses containing CR/LF or
// failing RFC 5322 parsing are rejected.
func NewSMTP(cfg config.SMTPCfg, timeout time.Duration) (*SMTP, error) {
	bad := func(msg string) (*SMTP, error) { return nil, fmt.Errorf("smtp %q: %s", cfg.Name, msg) }
	if cfg.Host == "" || strings.ContainsAny(cfg.Host, " \r\n/@") {
		return bad("invalid host")
	}
	if cfg.TLS == "" {
		cfg.TLS = "starttls"
	}
	switch cfg.TLS {
	case "starttls", "tls", "none":
	default:
		return bad("tls must be starttls, tls or none")
	}
	if cfg.Port == 0 {
		cfg.Port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[cfg.TLS]
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return bad("port out of range")
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return bad("username and password must be set together")
	}
	if cfg.TLS == "none" && cfg.Username != "" && !loopbackHost(cfg.Host) {
		return bad("refusing to send credentials without TLS to a non-loopback host")
	}
	from, err := parseAddr(cfg.From)
	if err != nil {
		return bad("invalid from address")
	}
	if len(cfg.To) == 0 {
		return bad("no recipients")
	}
	s := &SMTP{name: cfg.Name, cfg: cfg, from: from, timeout: timeout}
	for _, t := range cfg.To {
		a, err := parseAddr(t)
		if err != nil {
			return bad("invalid recipient address")
		}
		s.to = append(s.to, a)
	}
	if s.timeout <= 0 {
		s.timeout = 10 * time.Second
	}
	return s, nil
}

func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func parseAddr(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return nil, errors.New("control character in address")
	}
	return mail.ParseAddress(s)
}

// Name returns the configured sender name.
func (s *SMTP) Name() string { return s.name }

// Type is the bounded metrics label for this sender kind.
func (s *SMTP) Type() string { return "smtp" }

// Send delivers e to every recipient in one transaction.
func (s *SMTP) Send(ctx context.Context, e Event) error {
	e = e.normalized()
	msg, err := s.buildMessage(e)
	if err != nil {
		return fmt.Errorf("smtp %q: %w", s.name, err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if err := s.deliver(ctx, msg); err != nil {
		return fmt.Errorf("smtp %q: %w", s.name, s.wrapErr(err))
	}
	return nil
}

func (s *SMTP) wrapErr(err error) error {
	var te *textproto.Error
	perm := errors.As(err, &te) && te.Code >= 500
	err = scrub(err, s.cfg.Password.Reveal()) // password only: usernames are short and not secret
	if perm {
		return permanent(err)
	}
	return err
}

func (s *SMTP) buildMessage(e Event) ([]byte, error) {
	if err := checkHeaderValue("Subject", e.Subject); err != nil {
		return nil, err
	}
	subject := fmt.Sprintf("[doorwarden] %s %s", e.Severity, e.Subject)
	var rid [12]byte
	_, _ = rand.Read(rid[:])
	domain := "localhost"
	if i := strings.LastIndexByte(s.from.Address, '@'); i >= 0 {
		domain = s.from.Address[i+1:]
	}
	toHdr := make([]string, len(s.to))
	for i, a := range s.to {
		toHdr[i] = a.String()
	}
	hdrs := [][2]string{
		{"From", s.from.String()},
		{"To", strings.Join(toHdr, ", ")},
		{"Subject", mime.QEncoding.Encode("UTF-8", subject)},
		{"Date", time.Now().Format(time.RFC1123Z)},
		{"Message-ID", "<" + hex.EncodeToString(rid[:]) + "@" + domain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=UTF-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
		{"X-Doorwarden-Kind", e.Kind},
	}
	var b bytes.Buffer
	for _, h := range hdrs {
		v := h[1]
		if h[0] == "X-Doorwarden-Kind" {
			v = mime.QEncoding.Encode("UTF-8", v)
		}
		if err := checkHeaderValue(h[0], v); err != nil {
			return nil, err
		}
		b.WriteString(h[0] + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")
	var body bytes.Buffer
	body.WriteString(e.Message)
	body.WriteString("\n")
	if len(e.Fields) > 0 {
		body.WriteString("\n")
		for _, k := range sortedFields(e.Fields) {
			fmt.Fprintf(&body, "%s: %s\n", k, e.Fields[k])
		}
	}
	fmt.Fprintf(&body, "\nkind: %s\ntime: %s\n", e.Kind, e.At.Format(time.RFC3339))
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write(body.Bytes()); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (s *SMTP) tlsCfg() *tls.Config {
	if s.tlsConfig != nil {
		return s.tlsConfig.Clone()
	}
	return &tls.Config{
		ServerName:         s.cfg.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: s.cfg.InsecureSkipVerify, //nolint:gosec // explicit admin opt-in
	}
}

func (s *SMTP) deliver(ctx context.Context, msg []byte) error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connect: %w", unwrapOp(err))
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if s.cfg.TLS == "tls" {
		tc := tls.Client(conn, s.tlsCfg())
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("tls handshake: %w", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	defer c.Close()
	if s.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS (refusing to continue in plaintext)")
		}
		if err := c.StartTLS(s.tlsCfg()); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if s.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password.Reveal(), s.cfg.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, a := range s.to {
		if err := c.Rcpt(a.Address); err != nil {
			return fmt.Errorf("RCPT TO: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("end of data: %w", err)
	}
	_ = c.Quit()
	return nil
}

func unwrapOp(err error) error {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return fmt.Errorf("%s: %w", oe.Op, oe.Err)
	}
	return err
}
