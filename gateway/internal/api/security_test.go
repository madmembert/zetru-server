package api

// Regression tests for the findings of the Go security review (GO-xx in DECISIONS.md).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"zetru.app/gateway/internal/registry"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// rawDo sends a request without the result checks of send and returns status, body and
// signature header.
func (e *testEnv) rawDo(req *http.Request) (int, []byte, string) {
	e.t.Helper()
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, resp.Header.Get("Zetru-Signature")
}

// GO-10: a response is bound to the request it answers. A TLS-terminating proxy that sends its
// own request with the victim's nonce gets a signature that does not verify for the victim's
// request, whether the proxy's request is unauthenticated or signed by a device of its own.
func TestResponseIsBoundToTheRequest(t *testing.T) {
	e := newEnv(t)
	victim := e.enroll("victim")
	attackerTenant, _ := e.reg.CreateTenant("attacker")
	tok, _, _ := e.reg.CreateEnrolmentToken(attackerTenant.ID, registry.TokenTTL)
	key, pub := newKey(t)
	attackerDev, err := e.reg.Enroll(tok, pub, "attacker")
	if err != nil {
		t.Fatal(err)
	}
	attacker := device{id: attackerDev.ID, key: key}

	nonce := newNonce()
	victimReq, _ := e.signedRequest(victim, "GET", "/v1/devices", nil, nil, reqOpts{nonce: nonce})
	victimBinding := bindingOf(victimReq)

	// 1. Unauthenticated request with the victim's nonce: a signed 401 for the proxy's request only.
	own, _ := http.NewRequest("GET", e.base+"/v1/devices", nil)
	own.Header.Set("Zetru-Nonce", nonce)
	status, body, sig := e.rawDo(own)
	if status != 401 || !e.responseVerifies(nonce, bindingOf(own), status, body, sig) {
		t.Fatalf("own request: %d %s", status, body)
	}
	if e.responseVerifies(nonce, victimBinding, status, body, sig) {
		t.Fatal("a 401 for the proxy's request verifies for the victim's request")
	}
	// 2. The proxy's own device, same path, the victim's nonce: a signed 200 that does not verify
	//    for the victim (it would show the victim another tenant's device list).
	attackerReq, _ := e.signedRequest(attacker, "GET", "/v1/devices", nil, nil, reqOpts{nonce: nonce})
	status, body, sig = e.rawDo(attackerReq)
	if status != 200 || !e.responseVerifies(nonce, bindingOf(attackerReq), status, body, sig) {
		t.Fatalf("attacker request: %d %s", status, body)
	}
	if e.responseVerifies(nonce, victimBinding, status, body, sig) {
		t.Fatal("another device's 200 verifies for the victim's request")
	}
	// 3. The victim's own request still gets its own valid response.
	if r := e.send(victimReq, nonce); r.status != 200 {
		t.Fatalf("victim: %d", r.status)
	}
	// 4. The device ID is part of the signed canonical string: the victim's signature under
	//    another device ID is refused.
	swapped, _ := e.signedRequest(victim, "GET", "/v1/devices", nil, nil, reqOpts{})
	swapped.Header.Set("Zetru-Device", attacker.id)
	expect(t, "device swap", e.send(swapped, swapped.Header.Get("Zetru-Nonce")), 401, "bad_signature")
}

// stalledUpload starts an analyze upload that sends 10 bytes of its body and then stalls. With
// signed=false the signature is garbage. It returns a channel with the status (0 on a transport
// error) and a function that ends the upload.
func (e *testEnv) stalledUpload(d device, signed bool) (<-chan int, func()) {
	e.t.Helper()
	body := analyzeBody(e.t, testMail, nil)
	pr, pw := io.Pipe()
	o := reqOpts{contentType: AnalyzeContentType}
	if !signed {
		o.signer, _ = newKey(e.t)
	}
	req, _ := e.signedRequest(d, "POST", "/v1/analyze", pr, body, o)
	req.ContentLength = int64(len(body))
	status := make(chan int, 1)
	go func() {
		resp, err := e.client.Do(req)
		if err != nil {
			status <- 0
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		status <- resp.StatusCode
	}()
	go func() { _, _ = pw.Write(body[:10]) }()
	return status, func() { _ = pw.CloseWithError(errors.New("upload ended")) }
}

// GO-02 and GO-08: stalled uploads. Unsigned ones take no slot and no nonce; signed ones are
// limited per device (2) and per tenant (half of the slots), so another tenant still gets through;
// a stalled body is cut after the progress window, which frees its slot.
func TestStalledUploadsCannotBlockOtherTenants(t *testing.T) {
	e := newEnvWith(t, func(o *Options) { o.BodyProgressWindow = 1500 * time.Millisecond })
	a1, a2, a3 := e.enroll("a1"), e.enroll("a2"), e.enroll("a3")
	office, _ := e.reg.CreateTenant("office")
	tok, _, _ := e.reg.CreateEnrolmentToken(office.ID, registry.TokenTTL)
	key, pub := newKey(t)
	bDev, _ := e.reg.Enroll(tok, pub, "b")
	b := device{id: bDev.ID, key: key}
	var stops []func()
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()

	// Unsigned stalled uploads (anyone who knows a device ID): refused before the body is read.
	for i := 0; i < 12; i++ {
		status, stop := e.stalledUpload(a1, false)
		stops = append(stops, stop)
		if got := <-status; got != 401 {
			t.Fatalf("unsigned stalled upload: status %d", got)
		}
	}
	if n := e.srv.admission.inUse(); n != 0 {
		t.Fatalf("unsigned uploads hold %d analyze slots", n)
	}
	if n := e.srv.nonces.Len(a1.id); n != 0 {
		t.Fatalf("unsigned uploads hold %d nonces of the device", n)
	}

	// Signed stalled uploads: 2 per device, 5 (half of 10) per tenant.
	for _, d := range []device{a1, a1, a2, a2, a3} {
		_, stop := e.stalledUpload(d, true)
		stops = append(stops, stop)
	}
	waitFor(t, "5 uploads in flight", func() bool { return e.srv.admission.inUse() == 5 })
	expect(t, "third upload of one device", e.analyze(a1, testMail, reqOpts{}), 503, "busy")
	expect(t, "sixth upload of one tenant", e.analyze(a3, testMail, reqOpts{}), 503, "busy")
	if r := e.analyze(b, testMail, reqOpts{}); r.status != 200 {
		t.Fatalf("another tenant blocked by stalled uploads: %d %s", r.status, r.body)
	}
	// The progress window (1.5 s here, 5 s by default) cuts the stalled bodies.
	waitFor(t, "stalled uploads cut", func() bool { return e.srv.admission.inUse() == 0 })
	if r := e.analyze(a1, testMail, reqOpts{}); r.status != 200 {
		t.Fatalf("after the cut: %d %s", r.status, r.body)
	}

	// Analyze without Content-Length (chunked) is refused: the slot is sized by it.
	chunked, nonce := e.signedRequest(a2, "POST", "/v1/analyze", io.MultiReader(bytes.NewReader(analyzeBody(t, testMail, nil))),
		analyzeBody(t, testMail, nil), reqOpts{contentType: AnalyzeContentType})
	expect(t, "chunked analyze", e.send(chunked, nonce), 400, "bad_request")
}

// GO-03: requests that do not authenticate are counted per minute and key, not logged one line
// each.
func TestUnauthenticatedRequestsDoNotGrowTheLog(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	before := strings.Count(e.reqLog.String(), "\n")
	for i := 0; i < 300; i++ {
		req, _ := http.NewRequest("GET", e.base+"/nope", nil)
		e.send(req, "")
	}
	for i := 0; i < 100; i++ {
		e.analyze(d, testMail, reqOpts{deviceID: registry.NewID()})
	}
	if n := strings.Count(e.reqLog.String(), "\n") - before; n != 0 {
		t.Fatalf("%d lines written for unauthenticated requests", n)
	}
	_ = e.srv.opt.RequestLog.Close() // writes the pending counts
	lines := strings.Split(strings.TrimSpace(e.reqLog.String()), "\n")[before:]
	if len(lines) != 2 || !strings.Contains(strings.Join(lines, "\n"), `"endpoint":"unknown","status":404,"code":"not_found","count":300`) ||
		!strings.Contains(strings.Join(lines, "\n"), `"endpoint":"POST /v1/analyze","status":401,"code":"unknown_device","count":100`) {
		t.Fatalf("aggregated lines:\n%s", strings.Join(lines, "\n"))
	}
}

// GO-04: a client that disconnects after uploading neither gets its quota unit back nor stops
// the counter update.
func TestClientDisconnectKeepsTheQuotaUnit(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	e.analyzer.mu.Lock()
	e.analyzer.mode = "slow"
	e.analyzer.mu.Unlock()
	for i := 0; i < 3; i++ {
		body := analyzeBody(t, testMail, nil)
		req, _ := e.signedRequest(d, "POST", "/v1/analyze", bytes.NewReader(body), body, reqOpts{contentType: AnalyzeContentType})
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
				e.analyzer.mu.Lock()
				called := e.analyzer.calls > i
				e.analyzer.mu.Unlock()
				if called {
					break
				}
			}
			cancel() // the client resets the request while the analyzer works
		}()
		if resp, err := e.client.Do(req.WithContext(ctx)); err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("request was not cancelled: %d %s", resp.StatusCode, b)
		}
		cancel()
		// The analysis goes on without the client and keeps its slot until it is done.
		waitFor(t, "the detached analysis", func() bool { return e.srv.admission.inUse() == 0 })
	}
	waitFor(t, "counter updates", func() bool { _, tb, refs, _ := e.srv.opt.Campaign.Stats(); return tb > 0 && refs == 1 })
	waitFor(t, "quota", func() bool { return e.srv.opt.Quota.Count("analyze|"+d.id) == 3 })
	time.Sleep(300 * time.Millisecond) // a refund would come within the analyzer's 150 ms
	if n := e.srv.opt.Quota.Count("analyze|" + d.id); n != 3 {
		t.Fatalf("quota used %d after 3 cancelled analyses, want 3", n)
	}
}

// GO-07: case-variant and duplicate keys are refused wherever the gateway validates JSON that a
// case-sensitive reader reads afterwards.
func TestCaseVariantKeysAreRefused(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	e.analyzer.mu.Lock()
	e.analyzer.mode = "casesignal"
	e.analyzer.mu.Unlock()
	r := e.analyze(d, testMail, reqOpts{})
	expect(t, "case-variant signal", r, 503, "analyzer_unavailable")

	e.analyzer.mu.Lock()
	e.analyzer.mode = "urlcase"
	e.analyzer.mu.Unlock()
	body, _ := json.Marshal(map[string]any{"items": []map[string]any{{"host": "a.test", "url_sha256": strings.Repeat("a", 64)}}})
	expect(t, "case-variant url/check results", e.do(d, "POST", "/v1/url/check", body, reqOpts{}), 503, "analyzer_unavailable")

	// Request meta with a case variant next to the real key never reaches the analyzer.
	e.analyzer.mu.Lock()
	e.analyzer.mode = ""
	calls := e.analyzer.calls
	e.analyzer.mu.Unlock()
	sum := sha256.Sum256(testMail)
	meta := `{"schema":1,"mail_sha256":"` + hex.EncodeToString(sum[:]) + `","Mail_SHA256":"` + strings.Repeat("0", 64) +
		`","account_ref":"` + secretAccount + `","mode":"auto","locale":"de","catalog_version":1}`
	framed := make([]byte, 4, 4+len(meta)+len(testMail))
	binary.BigEndian.PutUint32(framed, uint32(len(meta)))
	framed = append(append(framed, meta...), testMail...)
	expect(t, "case-variant meta", e.do(d, "POST", "/v1/analyze", framed, reqOpts{contentType: AnalyzeContentType}), 400, "bad_request")
	if e.analyzer.calls != calls {
		t.Fatal("ambiguous meta reached the analyzer")
	}
	// A valid url/check answer is re-encoded from the validated values.
	r = e.do(d, "POST", "/v1/url/check", body, reqOpts{})
	if r.status != 200 || string(r.body) != `{"results":[{"url_sha256":"`+strings.Repeat("a", 64)+`","hit":false,"signal":null}],"feeds":[]}` {
		t.Fatalf("url/check: %d %s", r.status, r.body)
	}
}

func TestStrictObject(t *testing.T) {
	for _, bad := range []string{`{"a":1,"a":2}`, `{"id":1,"ID":2}`, `{"k":1,"K":2}`, `{"s":1,"ſ":1}`, `[1]`, `{"a":1} {}`, `{"a":`} {
		if _, err := strictObject([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	obj, err := strictObject([]byte(`{"id":"X","evidence":{"a":1}}`))
	if err != nil || string(obj["evidence"]) != `{"a":1}` {
		t.Fatalf("%v %s", err, obj["evidence"])
	}
	if exactKeys(map[string]json.RawMessage{"Id": nil}, "id") || !exactKeys(map[string]json.RawMessage{"idx": nil}, "id") {
		t.Fatal("exactKeys")
	}
}

// GO-11: after a restart the replay cache is empty, so requests signed before the start are
// refused while they could still be inside the timestamp window.
func TestRequestsSignedBeforeTheStartAreRefused(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	start := e.srv.started.Unix()
	expect(t, "signed 30 s before the start", e.do(d, "GET", "/v1/devices", nil, reqOpts{timestamp: start - 30}), 401, "stale_timestamp")
	if r := e.do(d, "GET", "/v1/devices", nil, reqOpts{timestamp: start}); r.status != 200 {
		t.Fatalf("signed at the start: %d", r.status)
	}
	e.advance(100 * time.Second)
	expect(t, "100 s after the start", e.do(d, "GET", "/v1/devices", nil, reqOpts{timestamp: start - 1}), 401, "stale_timestamp")
	if r := e.do(d, "GET", "/v1/devices", nil, reqOpts{timestamp: e.now().Unix() - 90}); r.status != 200 {
		t.Fatalf("lagging clock after the start: %d", r.status)
	}
}

// GO-13: unknown enrolment tokens are limited per address (IPv6 per /64) and globally; a valid
// token always passes.
func TestEnrolmentLimitsPerPrefixAndInTotal(t *testing.T) {
	e := newEnv(t)
	_, pub := newKey(t)
	post := func(remote, token string) int {
		data, _ := json.Marshal(map[string]any{"token": token, "device_public_key": pub, "device_label": "x",
			"app_version": "1.0", "platform": "ios"})
		req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(data))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		e.srv.ServeHTTP(rec, req)
		return rec.Code
	}
	unknown := "AAAAAAAAAAAAAAAAAAAAAA"
	for i := 1; i <= 5; i++ {
		if c := post(fmt.Sprintf("[2001:db8:1:2::%x]:5000", i), unknown); c != 403 {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	if c := post("[2001:db8:1:2:ffff:ffff:ffff:ffff]:1", unknown); c != 429 {
		t.Fatalf("same /64: %d, want 429", c)
	}
	if c := post("[2001:db8:1:3::1]:1", unknown); c != 403 {
		t.Fatalf("other /64: %d", c)
	}
	// 6 unknown tokens counted so far; 54 more from distinct addresses reach the global 60.
	for i := 0; i < 54; i++ {
		if c := post(fmt.Sprintf("198.51.100.%d:1", i+1), unknown); c != 403 {
			t.Fatalf("address %d: %d", i, c)
		}
	}
	if c := post("203.0.113.9:1", unknown); c != 429 {
		t.Fatalf("global limit: %d, want 429", c)
	}
	tok, _, _ := e.reg.CreateEnrolmentToken(e.tenant.ID, registry.TokenTTL)
	if c := post("203.0.113.9:1", tok); c != 200 {
		t.Fatalf("valid token during the limit: %d", c)
	}
	if ClientKey("[::ffff:192.0.2.1]:1") != "192.0.2.1" || ClientKey("[fe80::1%eth0]:1") != "fe80::/64" || ClientKey("pipe") != "pipe" {
		t.Fatal("ClientKey")
	}
}

// GO-18: format characters are removed from device labels before they are stored and listed.
func TestDeviceLabelsAreCleaned(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("Max‮ enohPi​")
	r := e.do(d, "GET", "/v1/devices", nil, reqOpts{})
	var list struct {
		Devices []deviceEntry `json:"devices"`
	}
	if err := json.Unmarshal(r.body, &list); err != nil || len(list.Devices) != 1 || list.Devices[0].Label != "Max enohPi" {
		t.Fatalf("devices: %s", r.body)
	}
	expect(t, "control character", e.enrollRaw(map[string]any{"token": "AAAAAAAAAAAAAAAAAAAAAA", "device_public_key": "x",
		"device_label": "a\nb", "app_version": "1", "platform": "ios"}, ""), 400, "bad_request")
}

// fakeConnListener hands out in-memory connections with a chosen remote address.
type fakeConnListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

type addrConn struct {
	net.Conn
	remote string
}

func (c addrConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP(c.remote), Port: 1} }

func (l *fakeConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *fakeConnListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *fakeConnListener) Addr() net.Addr { return memAddr{} }

// GO-12: the listener limits connections in total and per address.
func TestLimitListener(t *testing.T) {
	fl := &fakeConnListener{conns: make(chan net.Conn, 16), closed: make(chan struct{})}
	ll := LimitListener(fl, 3, 2)
	defer ll.Close()
	dial := func(ip string) net.Conn {
		server, client := net.Pipe()
		fl.conns <- addrConn{Conn: server, remote: ip}
		return client
	}
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	next := func() net.Conn {
		select {
		case c := <-accepted:
			return c
		case <-time.After(time.Second):
			return nil
		}
	}
	c1 := dial("192.0.2.1")
	a1 := next()
	dial("192.0.2.1")
	a2 := next()
	third := dial("192.0.2.1") // a third connection from the same address is closed
	_ = third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := third.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("third connection from one address not closed: %v", err)
	}
	dial("2001:db8::1")
	a3 := next()
	if a1 == nil || a2 == nil || a3 == nil {
		t.Fatal("connections within the limits were not accepted")
	}
	dial("2001:db8::2") // total limit 3 reached: waits
	if c := next(); c != nil {
		t.Fatal("total limit not enforced")
	}
	_ = a1.Close()
	if c := next(); c == nil {
		t.Fatal("slot not released on close")
	}
	_ = c1.Close()
}
