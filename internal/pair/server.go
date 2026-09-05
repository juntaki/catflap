package pair

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is a pairing rendezvous: it stores sealed envelopes indexed by
// random id and hands each out exactly once. It CANNOT read envelopes
// (ciphertext only) and it relays no task traffic.
//
// Abuse controls: per-IP fixed-window rate limits on publish and fetch, a
// cap on stored envelopes, live ids that cannot be overwritten (409), and
// server-side TTL with sweep-on-write. Missing, expired, and consumed ids
// all answer the same 404: no oracle beyond that.
//
// Client identity is the TCP peer. Behind a reverse proxy, pass the proxy
// CIDRs via SetTrustedProxies so the nearest non-trusted-proxy entry in
// X-Forwarded-For is used (scanned from the right, peeling known proxy
// hops — a proxy only appends what it saw, so the leftmost entry is
// whatever the client itself wrote and is never safe to trust); XFF is
// never consulted otherwise. Terminating TLS in front is a deployment
// concern, not a protocol one.
type Server struct {
	mu        sync.Mutex
	items     map[string]stored
	maxItems  int
	publishes *limiter
	fetches   *limiter
	trusted   []*net.IPNet
}

type stored struct {
	body    []byte
	expires time.Time
}

// NewServer builds a rendezvous holding at most maxItems envelopes, with
// publish/fetch per-IP per-minute budgets. Non-positive inputs take safe
// defaults (10000 items, 10 publishes/min, 60 fetches/min).
func NewServer(maxItems, publishPerMin, fetchPerMin int) *Server {
	if maxItems <= 0 {
		maxItems = 10000
	}
	if publishPerMin <= 0 {
		publishPerMin = 10
	}
	if fetchPerMin <= 0 {
		fetchPerMin = 60
	}
	return &Server{
		items:     map[string]stored{},
		maxItems:  maxItems,
		publishes: newLimiter(publishPerMin),
		fetches:   newLimiter(fetchPerMin),
	}
}

// SetTrustedProxies configures CIDRs whose X-Forwarded-For is honored for
// rate limiting. Parse errors fail the whole update.
func (s *Server) SetTrustedProxies(cidrs []string) error {
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, parsed, err := net.ParseCIDR(c)
		if err != nil {
			ip := net.ParseIP(strings.TrimSpace(c))
			if ip == nil {
				return fmt.Errorf("bad trusted proxy %q", c)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			parsed = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		nets = append(nets, parsed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trusted = nets
	return nil
}

// Handler serves the rendezvous API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/envelopes", s.handlePublish)
	mux.HandleFunc("/v1/envelopes/", s.handleFetch)
	return mux
}

// clientIP resolves the rate-limit identity: TCP peer, or — only when the
// peer is a configured trusted proxy — the nearest X-Forwarded-For entry
// not itself a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	s.mu.Lock()
	trusted := s.trusted
	s.mu.Unlock()
	if len(trusted) == 0 {
		return host
	}
	peer := net.ParseIP(host)
	if peer == nil || !isTrustedIP(peer, trusted) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	// Peel trusted hops from the right: a proxy APPENDS the address it
	// saw, it never overwrites what's already there, so a client can
	// prepend an arbitrary spoofed entry to the left of whatever the
	// trusted proxy adds. Scanning left-to-right and taking the first
	// entry (the old bug) trusts exactly what the client wrote. Scanning
	// from the right and stopping at the first entry that is NOT itself
	// one of our trusted proxies finds the address the nearest trusted
	// hop actually observed, which the client cannot forge.
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(parts[i]))
		if candidate == nil {
			continue
		}
		if isTrustedIP(candidate, trusted) {
			continue
		}
		return candidate.String()
	}
	return host
}

func isTrustedIP(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.publishes.allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate limited, retry later")
		return
	}
	ttl := DefaultEnvelopeTTL
	if q := r.URL.Query().Get("ttl_seconds"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n <= 0 || time.Duration(n)*time.Second > MaxEnvelopeTTL {
			writeError(w, http.StatusBadRequest, "ttl_seconds must be within (0, 600]")
			return
		}
		ttl = time.Duration(n) * time.Second
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, MaxEnvelopeBytes+1024))
	env, err := DecodeEnvelope(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("bad envelope: %v", err))
		return
	}
	if !validID(env.ID) {
		writeError(w, http.StatusBadRequest, "bad envelope id")
		return
	}
	// Server owns expiry: ignore client timestamps, stamp our own.
	env.ExpiresAt = time.Now().Add(ttl)
	sealed, err := EncodeEnvelope(env)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("bad envelope: %v", err))
		return
	}
	s.mu.Lock()
	s.sweepLocked()
	if _, exists := s.items[env.ID]; exists {
		// Live ids are never overwritten: id squatting fails instead of
		// replacing someone else's envelope (or masking a replay).
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "id already registered")
		return
	}
	if len(s.items) >= s.maxItems {
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "rendezvous full, retry later")
		return
	}
	s.items[env.ID] = stored{body: sealed, expires: env.ExpiresAt}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	respRaw, merr := json.Marshal(PublishResponse{ID: env.ID})
	if merr != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	_, _ = w.Write(respRaw)
}

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.fetches.allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate limited, retry later")
		return
	}
	id := r.URL.Path[len("/v1/envelopes/"):]
	if !validID(id) {
		writeError(w, http.StatusNotFound, "no such pairing")
		return
	}
	s.mu.Lock()
	s.sweepLocked()
	item, ok := s.items[id]
	if ok {
		delete(s.items, id) // single-use: burn on fetch
	}
	s.mu.Unlock()
	if !ok {
		// Same 404 for missing, expired, and consumed: no oracle.
		writeError(w, http.StatusNotFound, "no such pairing")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(item.body)
}

// sweepLocked drops expired envelopes. Called under mu on every request;
// expiry is also re-checked implicitly since only live items are stored.
func (s *Server) sweepLocked() {
	now := time.Now()
	for id, item := range s.items {
		if !item.expires.After(now) {
			delete(s.items, id)
		}
	}
}

// idLen matches Mint's id shape exactly (48-bit locator, hex-encoded).
// publish and fetch both enforce it via validID, so an id that could
// never be fetched (wrong length/charset) can never be published either
// — otherwise it would sit occupying a maxItems slot until its TTL with
// no way for anyone to ever burn it early.
const idLen = 12

func validID(id string) bool {
	if len(id) != idLen {
		return false
	}
	for _, c := range []byte(id) {
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			return false
		}
	}
	return true
}

// limiter is a per-key fixed-window counter.
type limiter struct {
	mu     sync.Mutex
	budget int
	hits   map[string]*window
}

type window struct {
	count int
	reset time.Time
}

// maxLimiterIdentities bounds the limiter's map, independent of how many
// requests arrive: an unbounded number of distinct identities (spoofed
// XFF entries, IPv6 rotation, etc.) must not grow this without limit,
// since the old "sweep past 100000" check never actually capped size —
// if every tracked identity was still within its current window, nothing
// was ever evicted, and the sweep itself became an O(n) cost on every
// call once past the threshold.
const maxLimiterIdentities = 100000

func newLimiter(perMin int) *limiter {
	return &limiter{budget: perMin, hits: map[string]*window{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.hits[key]
	switch {
	case ok && !w.reset.After(now):
		// Known identity, window rolled over: reset in place, no growth.
		w.count = 0
		w.reset = now.Add(time.Minute)
	case !ok:
		if len(l.hits) >= maxLimiterIdentities {
			for k, v := range l.hits {
				if !v.reset.After(now) {
					delete(l.hits, k)
				}
			}
		}
		if len(l.hits) >= maxLimiterIdentities {
			// Still full after sweeping stale entries: deny the new
			// identity rather than grow past the bound. Identities
			// already tracked keep working normally.
			return false
		}
		w = &window{reset: now.Add(time.Minute)}
		l.hits[key] = w
	}
	if w.count >= l.budget {
		return false
	}
	w.count++
	return true
}
