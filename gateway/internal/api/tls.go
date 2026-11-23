package api

import (
	"crypto/tls"
	"io"
	"log"
	"log/slog"
	"strings"
)

// TLSConfig returns the server TLS settings of §4.3: TLS 1.3 only (Go's TLS 1.3 suites are exactly
// TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256), no client
// certificates, HTTP/2 allowed. Session ticket keys are generated randomly per process, so tickets
// never survive a restart. The certificate comes from getCert so that a promoted key is served
// without a restart.
func TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
		GetCertificate: getCert,
		ClientAuth:     tls.NoClientCert,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// ServerErrorLog returns a *log.Logger for http.Server.ErrorLog that never writes the message
// text: net/http includes client addresses in its messages ("TLS handshake error from <ip>"),
// and §11.5 forbids logging them. TLS handshake errors (scanners, clients with a wrong pin) are
// dropped; anything else is logged as a fixed class.
func ServerErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(serverErrorWriter{logger}, "", 0)
}

type serverErrorWriter struct{ log *slog.Logger }

func (w serverErrorWriter) Write(p []byte) (int, error) {
	msg := string(p)
	switch {
	case strings.Contains(msg, "TLS handshake error"):
	case strings.Contains(msg, "panic"):
		w.log.Error("http server error", "class", "panic")
	default:
		w.log.Warn("http server error", "class", "http_server")
	}
	return len(p), nil
}

var _ io.Writer = serverErrorWriter{}
