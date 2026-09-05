package pair

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Server is a pairing rendezvous: it stores sealed envelopes indexed by
// random id and hands each out exactly once. It CANNOT read envelopes
// (ciphertext only) and it relays no task traffic.
//
// Abuse controls: per-IP fixed-window rate limits on publish and fetch,
// a cap on stored envelopes, server-side TTL with sweep-on-write, and a
// 404 for anything missing/expired/consumed (no oracle beyond that).
//
// Deployment note: terminate TLS in front (reverse proxy); never trust
// X-Forwarded-For here — client identity is the TCP peer.
type Server struct {
	mu        sync.Mutex
	items     map[string]stored
	maxItems  int
	publishes *limiter
	fetches   *limiter
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

// Handler serves the rendezvous API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/envelopes", s.handlePublish)
	mux.HandleFunc("/v1/envelopes/", s.handleFetch)
	return mux
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.publishes.allow(clientIP(r)) {
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
	if env.ID == "" || len(env.ID) > 64 {
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
	if len(s.items) >= s.maxItems {
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "rendezvous full, retry later")
		return
	}
	s.items[env.ID] = stored{body: sealed, expires: env.ExpiresAt}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	raw, _ = json.Marshal(PublishResponse{ID: env.ID})
	_, _ = w.Write(raw)
}

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.fetches.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "rate limited, retry later")
		return
	}
	id := r.URL.Path[len("/v1/envelopes/"):]
	if id == "" || len(id) > 64 || !validID(id) {
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

func validID(id string) bool {
	for _, c := range []byte(id) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return len(id) > 0
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

func newLimiter(perMin int) *limiter {
	return &limiter{budget: perMin, hits: map[string]*window{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.hits[key]
	if !ok || !w.reset.After(now) {
		w = &window{reset: now.Add(time.Minute)}
		l.hits[key] = w
	}
	// Bound map growth: drop stale windows opportunistically.
	if len(l.hits) > 100000 {
		for k, v := range l.hits {
			if !v.reset.After(now) {
				delete(l.hits, k)
			}
		}
	}
	if w.count >= l.budget {
		return false
	}
	w.count++
	return true
}
