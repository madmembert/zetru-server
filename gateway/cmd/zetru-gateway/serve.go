package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"zetru.app/gateway/internal/api"
	"zetru.app/gateway/internal/auth"
	"zetru.app/gateway/internal/campaign"
	"zetru.app/gateway/internal/config"
	"zetru.app/gateway/internal/fsutil"
	"zetru.app/gateway/internal/keys"
	"zetru.app/gateway/internal/limits"
	"zetru.app/gateway/internal/registry"
	"zetru.app/gateway/internal/reqlog"
)

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	profile, err := config.ProfileFor(os.Getenv("ZETRU_PROFILE"))
	if err != nil {
		return err
	}
	cfg, err := config.Load(*dir)
	if err != nil {
		return err
	}
	mgr, err := keys.NewManager(*dir)
	if err != nil {
		return err
	}
	reg, err := registry.Open(*dir, nil)
	if err != nil {
		return err
	}
	stateDir := filepath.Join(*dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	// Counter files of earlier versions (JSON format, moved-aside copies) would otherwise outlive
	// the 30-day retention of §14.2 (GO-17).
	for _, old := range []string{"campaign.json", "campaign.json.discarded"} {
		if err := fsutil.RemoveIfExists(filepath.Join(stateDir, old)); err != nil {
			return err
		}
	}
	counters, err := campaign.Open(filepath.Join(stateDir, "campaign.dat"), mgr.Material().Fingerprint, nil,
		campaign.Limits{MaxBands: profile.CampaignMaxBands, MaxRefs: profile.CampaignMaxRefs})
	if err != nil {
		return err
	}
	quota, err := limits.OpenQuota(filepath.Join(stateDir, "quota.json"), nil)
	if err != nil {
		return err
	}
	var reqLog *reqlog.Logger
	switch mode := envOr("ZETRU_REQUEST_LOG", "file"); mode {
	case "file":
		if reqLog, err = reqlog.NewFileLogger(filepath.Join(*dir, "logs"), nil); err != nil {
			return err
		}
	case "stdout":
		reqLog = reqlog.NewWriterLogger(os.Stdout)
	case "off":
		reqLog = reqlog.Discard()
	default:
		return fmt.Errorf("ZETRU_REQUEST_LOG must be file, stdout or off, not %q", mode)
	}
	defer reqLog.Close()

	srv := api.New(api.Options{
		Profile: profile, ServerName: cfg.Name, Version: version,
		AnalyzerURL: envOr("ZETRU_ANALYZER_URL", "http://analyzer:8081"),
		Registry:    reg, Keys: mgr, Campaign: counters, Quota: quota, RequestLog: reqLog, ErrorLog: logger,
	})
	srv.SaveState() // drop data of tenants deleted while the server was down

	listener, err := net.Listen("tcp", envOr("ZETRU_LISTEN", ":8443"))
	if err != nil {
		return err
	}
	// Bounded connections: in total and per client address (IPv6: per /64), GO-12.
	listener = api.LimitListener(listener, profile.MaxConns, profile.MaxConnsPerAddr)
	httpServer := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       api.DefaultReadTimeout, // a 20 MB mail over a slow mobile uplink
		WriteTimeout:      150 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 32},
		ErrorLog:          api.ServerErrorLog(logger),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	maintained := make(chan struct{})
	go func() {
		srv.Maintain(ctx, 5*time.Minute)
		close(maintained)
	}()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				before := mgr.Material().PinSet.Seq
				if err := mgr.Tick(time.Now()); err != nil {
					logger.Error("key material reload failed; serving the previous keys", "class", "keys")
				} else if seq := mgr.Material().PinSet.Seq; seq != before {
					logger.Info("pin set updated", "seq", seq)
				}
			}
		}
	}()

	logger.Info("gateway started", "version", version, "profile", profile.Name, "pin_set_seq", mgr.Material().PinSet.Seq)
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(tls.NewListener(listener, api.TLSConfig(mgr.GetCertificate))) }()
	select {
	case err := <-errCh:
		stop()
		<-maintained
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdown)
	<-maintained
	logger.Info("gateway stopped")
	return nil
}

// cmdHealthcheck connects to the local gateway, checks that it presents a pinned key and that the
// /healthz response carries a valid identity signature. It is the container healthcheck
// (distroless images have no curl).
func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	dir := dataDirFlag(fs)
	addr := fs.String("addr", "", "address to check (default 127.0.0.1 and the port of $ZETRU_LISTEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mat, err := keys.Load(*dir)
	if err != nil {
		return err
	}
	target := *addr
	if target == "" {
		_, port, err := net.SplitHostPort(envOr("ZETRU_LISTEN", ":8443"))
		if err != nil {
			return err
		}
		target = net.JoinHostPort("127.0.0.1", port)
	}
	pins := map[string]bool{}
	for _, p := range mat.PinSet.Pins {
		pins[p] = true
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // the pin check below replaces CA validation (§4.3, pin_only)
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if !pins[base64.StdEncoding.EncodeToString(sum[:])] {
				return errors.New("served key is not pinned")
			}
			return nil
		},
	}}}
	resp, err := client.Get("https://" + target + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	// The request carries no Zetru headers: nonce and binding cover empty values (§4.5).
	binding := auth.RequestBinding(auth.CanonicalString(http.MethodGet, "/healthz", "", "", "", ""))
	if !auth.VerifyResponse(mat.Identity.Public().(ed25519.PublicKey), "", resp.StatusCode, body, binding, resp.Header.Get(auth.HeaderSignature)) {
		return errors.New("response signature invalid")
	}
	return nil
}
