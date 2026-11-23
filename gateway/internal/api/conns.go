package api

import (
	"net"
	"net/netip"
	"sync"
)

// ClientKey is the key under which a client address is limited: the IPv4 address, or the /64 of
// an IPv6 address (one subscriber usually holds a whole /64, GO-13). Unparsable addresses are
// used as they are.
func ClientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.WithZone("").Unmap()
	if ip.Is4() {
		return ip.String()
	}
	prefix, _ := ip.Prefix(64)
	return prefix.String()
}

// LimitListener bounds the open connections of a listener: at most total at once (Accept waits
// for a free slot) and at most perAddr per ClientKey (further connections from that address are
// closed right away). Standard library only (GO-12).
func LimitListener(l net.Listener, total, perAddr int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, total), perAddr: perAddr,
		counts: map[string]int{}, closed: make(chan struct{})}
}

type limitListener struct {
	net.Listener
	sem     chan struct{}
	perAddr int

	mu     sync.Mutex
	counts map[string]int

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		select {
		case l.sem <- struct{}{}:
		case <-l.closed:
			return nil, net.ErrClosed
		}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		key := ClientKey(c.RemoteAddr().String())
		l.mu.Lock()
		if l.counts[key] >= l.perAddr {
			l.mu.Unlock()
			_ = c.Close()
			<-l.sem
			continue
		}
		l.counts[key]++
		l.mu.Unlock()
		return &limitedConn{Conn: c, release: func() {
			l.mu.Lock()
			if l.counts[key]--; l.counts[key] <= 0 {
				delete(l.counts, key)
			}
			l.mu.Unlock()
			<-l.sem
		}}, nil
	}
}

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
