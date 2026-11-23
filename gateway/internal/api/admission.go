package api

import (
	"io"
	"net/http"
	"sync"
	"time"
)

// admission bounds concurrent analyze uploads: in total (workers + queue of the profile), per
// tenant (half of the total) and per device (DefaultAnalyzePerDevice). A slot is taken only after
// the request signature has been verified, so only key holders can occupy slots; the per-tenant
// and per-device shares keep one tenant or device from taking all of them (GO-02).
type admission struct {
	mu                                sync.Mutex
	total                             int
	maxTotal, maxPerTenant, maxPerDev int
	perTenant, perDevice              map[string]int
}

// DefaultAnalyzePerDevice is the number of concurrent analyze uploads one device may hold.
const DefaultAnalyzePerDevice = 2

func newAdmission(slots, perDevice int) *admission {
	return &admission{maxTotal: slots, maxPerTenant: max(slots/2, 1), maxPerDev: perDevice,
		perTenant: map[string]int{}, perDevice: map[string]int{}}
}

func (a *admission) acquire(device, tenant string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.maxTotal || a.perTenant[tenant] >= a.maxPerTenant || a.perDevice[device] >= a.maxPerDev {
		return false
	}
	a.total++
	a.perTenant[tenant]++
	a.perDevice[device]++
	return true
}

func (a *admission) release(device, tenant string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total--
	if a.perTenant[tenant]--; a.perTenant[tenant] <= 0 {
		delete(a.perTenant, tenant)
	}
	if a.perDevice[device]--; a.perDevice[device] <= 0 {
		delete(a.perDevice, device)
	}
}

func (a *admission) inUse() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.total
}

// progressReader enforces a minimum upload rate on a request body: every minBytes must arrive
// within window of the previous minBytes, and the whole body within the request's overall read
// deadline. It moves the connection's read deadline forward through http.ResponseController
// (GO-02: a stalled upload is cut after window instead of holding its slot for the read timeout).
type progressReader struct {
	r        io.Reader
	ctrl     *http.ResponseController
	window   time.Duration
	minBytes int64
	overall  time.Time
	got      int64
	ok       bool
}

func (p *progressReader) arm() {
	d := time.Now().Add(p.window)
	if d.After(p.overall) {
		d = p.overall
	}
	p.ok = p.ctrl.SetReadDeadline(d) == nil // false where unsupported (then only ReadTimeout applies)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.got += int64(n)
	if p.ok && p.got >= p.minBytes {
		p.got = 0
		p.arm()
	}
	return n, err
}

// done puts the read deadline back to the request's overall deadline (the http.Server's
// ReadTimeout), so a deadline armed for the body cannot fire while the analyzer works.
func (p *progressReader) done() {
	if p.ok {
		_ = p.ctrl.SetReadDeadline(p.overall)
	}
}
