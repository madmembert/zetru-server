// Command zetru-lookup serves RDAP domain ages to the analyzer (docs/server-internal-api.md):
//
//	zetru-lookup serve        listen on $ZETRU_LOOKUP_LISTEN (default :8083)
//	zetru-lookup healthcheck  container healthcheck against the local instance
//
// Environment: ZETRU_LOOKUP_CACHE_DIR (default /cache), ZETRU_RDAP_RATE (requests per second and
// registry host, default 1), ZETRU_RDAP_BURST (default 6), ZETRU_RDAP_SUPPLEMENT (optional JSON
// file whose entries are added to, or replace, the built-in supplementary map).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"zetru.app/lookup/internal/rdap"
	"zetru.app/lookup/internal/service"
)

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envFloat(name string, def float64) (float64, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 || f > 100 {
		return 0, fmt.Errorf("%s must be a number between 0 and 100", name)
	}
	return f, nil
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	default:
		fmt.Fprintln(os.Stderr, "usage: zetru-lookup serve | healthcheck")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadSupplement() (rdap.Supplement, error) {
	supplement, err := rdap.DefaultSupplement()
	if err != nil {
		return nil, err
	}
	if path := os.Getenv("ZETRU_RDAP_SUPPLEMENT"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		extra, err := rdap.ParseSupplement(data)
		if err != nil {
			return nil, err
		}
		for tld, e := range extra {
			supplement[tld] = e
		}
	}
	return supplement, nil
}

func serve() error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	rate, err := envFloat("ZETRU_RDAP_RATE", 1)
	if err != nil {
		return err
	}
	burst, err := envFloat("ZETRU_RDAP_BURST", 6)
	if err != nil {
		return err
	}
	supplement, err := loadSupplement()
	if err != nil {
		return err
	}
	cacheDir := envOr("ZETRU_LOOKUP_CACHE_DIR", "/cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return err
	}
	svc, err := service.New(service.Options{
		CacheDir: cacheDir, HTTP: rdap.NewHTTPClient(), Limiter: rdap.NewHostLimiter(rate, burst, time.Second),
		Supplement: supplement, Log: logger,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() { // bootstrap: refresh daily, retry hourly after a failure
		for {
			wait := time.Hour
			if age, ok := svc.BootstrapAge(); ok && age < 24*time.Hour {
				wait = 24*time.Hour - age
			} else if err := svc.RefreshBootstrap(ctx); err != nil {
				logger.Error("bootstrap refresh failed", "class", "bootstrap")
			} else {
				logger.Info("bootstrap refreshed")
				wait = 24 * time.Hour
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := svc.Save(); err != nil {
					logger.Error("saving the cache failed", "class", "storage")
				}
			}
		}
	}()

	server := &http.Server{Addr: envOr("ZETRU_LOOKUP_LISTEN", ":8083"), Handler: svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	logger.Info("lookup started")
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	return svc.Save()
}

func healthcheck() error {
	_, port, err := net.SplitHostPort(envOr("ZETRU_LOOKUP_LISTEN", ":8083"))
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("unhealthy")
	}
	return nil
}
