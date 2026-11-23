package rdap

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{"Example.COM": "example.com", "example.com.": "example.com", "a.b.co.uk": "a.b.co.uk",
		"xn--bcher-kva.ch": "xn--bcher-kva.ch", "x.xn--p1ai": "x.xn--p1ai"}
	for in, want := range good {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q -> %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "com", "a..com", "-a.com", "a-.com", "1.2.3.4", "a.123", "a_b.com", "ä.com", "a.com/x", "a com.de"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseBootstrapAndSupplement(t *testing.T) {
	b, err := ParseBootstrap([]byte(`{"version":"1.0","publication":"x","services":[
		[["COM"],["http://plain.example/","https://rdap.example/v1"]],
		[["org"],["http://only-http.example/"]],
		[["bad tld"],["https://x.example/"]]]}`))
	if err != nil {
		t.Fatal(err)
	}
	if u := b.Lookup("com"); len(u) != 1 || u[0].String() != "https://rdap.example/v1/" {
		t.Fatalf("com: %v", u)
	}
	if len(b.Lookup("org")) != 0 || b.HasHost("plain.example") || !b.HasHost("rdap.example") {
		t.Fatal("http base URLs must be dropped")
	}
	for _, bad := range []string{`{}`, `{"version":"2.0","services":[[["a"],["https://a.example/"]]]}`, `{"version":"1.0","services":[[["a"]]]}`} {
		if _, err := ParseBootstrap([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	s, err := DefaultSupplement()
	if err != nil {
		t.Fatal(err)
	}
	for _, tld := range []string{"de", "ch"} {
		if _, noDate, ok := s.Bases(tld); !ok || !noDate {
			t.Fatalf(".%s must be marked as publishing no registration date", tld)
		}
	}
	if bases, noDate, ok := s.Bases("io"); !ok || noDate || len(bases) != 1 || bases[0].Scheme != "https" {
		t.Fatal(".io must map to its registry's RDAP service")
	}
	for _, bad := range []string{`{"DE":{"no_registration_date":true}}`, `{"x":{"urls":["http://a/"]}}`, `{"x":{}}`} {
		if _, err := ParseSupplement([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestDialGuard(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:443", "[2001:4860:4860::8888]:443"} {
		if err := guardedDialControl("tcp", addr, nil); err != nil {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
	for _, addr := range []string{"8.8.8.8:80", "127.0.0.1:443", "10.1.2.3:443", "172.20.0.5:443", "192.168.1.1:443",
		"169.254.169.254:443", "100.64.0.1:443", "[::1]:443", "[fd00::1]:443", "[fe80::1]:443", "0.0.0.0:443", "198.18.0.1:443"} {
		if err := guardedDialControl("tcp", addr, nil); err == nil {
			t.Errorf("%s allowed", addr)
		}
	}
	if publicIP(netip.Addr{}) {
		t.Fatal("invalid IP is public")
	}
}

// TestDialGuardSpecialRanges is the regression test for GO-14: NAT64, 6to4, Teredo, deprecated
// and documentation ranges reach private or unintended addresses and must be refused.
func TestDialGuardSpecialRanges(t *testing.T) {
	for _, addr := range []string{
		"[64:ff9b::a00:1]:443", "[64:ff9b:1::1]:443", "[2002:a00:1::1]:443", "[2001:0:4136:e378:8000:63bf:3fff:fdd2]:443",
		"[::10.0.0.1]:443", "[::ffff:10.0.0.1]:443", "[::ffff:127.0.0.1]:443", "[fec0::1]:443", "[fc00::1]:443",
		"[2001:db8::1]:443", "[3fff::1]:443", "[100::1]:443", "[ff02::1]:443", "[::]:443", "[fe80::1%25eth0]:443",
		"192.0.2.1:443", "198.51.100.1:443", "203.0.113.1:443", "192.88.99.1:443", "224.0.0.1:443", "255.255.255.255:443",
	} {
		if err := guardedDialControl("tcp", addr, nil); err == nil {
			t.Errorf("%s allowed", addr)
		}
	}
	for _, addr := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443", "[::ffff:8.8.8.8]:443", "[2a00:1450:4001::1]:443"} {
		if err := guardedDialControl("tcp", addr, nil); err != nil {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
}

func TestHostLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewHostLimiter(1, 2, 1500*time.Millisecond)
	l.Now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := l.Wait(ctx, "a"); err != nil {
			t.Fatal(err)
		}
	}
	short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if err := l.Wait(short, "a"); err != ErrRateLimited {
		t.Fatalf("waited past the caller's deadline: %v", err)
	}
	start := time.Now()
	if err := l.Wait(ctx, "a"); err != nil || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("expected a ~1 s wait: %v %v", err, time.Since(start))
	}
	if err := l.Wait(ctx, "b"); err != nil {
		t.Fatal("hosts must have separate buckets")
	}
	l.BackOff("b", time.Hour)
	if err := l.Wait(ctx, "b"); err != ErrRateLimited {
		t.Fatal("back-off ignored")
	}
	now = now.Add(16 * time.Minute) // capped at 15 minutes
	if err := l.Wait(ctx, "b"); err != nil {
		t.Fatalf("back-off not capped: %v", err)
	}
}

func TestParseDomainResponse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := map[string]Result{
		`{"objectClassName":"domain","events":[{"eventAction":"registration","eventDate":"1997-09-15T04:00:00Z"}]}`: {Status: StatusOK, RegisteredOn: 874296000},
		`{"objectClassName":"domain","events":[]}`: {Status: StatusUnknown},
		`{"objectClassName":"entity"}`:             {Status: StatusError},
		`not json`:                                 {Status: StatusError},
		`{"events":[{"eventAction":"registration","eventDate":"yesterday"}]}`:            {Status: StatusUnknown},
		`{"events":[{"eventAction":"registration","eventDate":"1970-01-01T00:00:00Z"}]}`: {Status: StatusUnknown},
	}
	for in, want := range cases {
		if got := parseDomainResponse([]byte(in), now); got != want {
			t.Errorf("%s: %+v, want %+v", in, got, want)
		}
	}
}
