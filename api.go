package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxSmallBody  = 64 << 10
	maxPushBody   = 32 << 20
	maxPushCount  = 1000
	maxRecordID   = 64
	maxDeviceName = 128
)

// Server serves the sync API.
type Server struct {
	store      *Store
	secret     []byte
	logins     *limiter
	trustProxy bool
}

func newServer(store *Store, trustProxy bool) (*Server, error) {
	secret, err := store.secret("prelogin")
	if err != nil {
		return nil, err
	}
	return &Server{
		store:      store,
		secret:     secret,
		logins:     newLimiter(10, 15*time.Minute),
		trustProxy: trustProxy,
	}, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/prelogin", s.prelogin)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.authed(s.logout))
	mux.HandleFunc("GET /api/vault-key", s.authed(s.getVaultKey))
	mux.HandleFunc("PUT /api/vault-key", s.authed(s.putVaultKey))
	mux.HandleFunc("GET /api/records", s.authed(s.pullRecords))
	mux.HandleFunc("POST /api/records", s.authed(s.pushRecords))
	return logRequests(mux)
}

type usernameRequest struct {
	Username string `json:"username"`
}

func (s *Server) prelogin(w http.ResponseWriter, r *http.Request) {
	var req usernameRequest
	if !readJSON(w, r, maxSmallBody, &req) {
		return
	}
	u, err := s.store.user(req.Username)
	switch {
	case errors.Is(err, errNoUser):
		writeJSON(w, http.StatusOK, paramsFor(fakeSalt(s.secret, req.Username)))
	case err != nil:
		serverError(w, err)
	default:
		writeJSON(w, http.StatusOK, paramsFor(u.KdfSalt))
	}
}

type loginRequest struct {
	Username string `json:"username"`
	AuthKey  []byte `json:"auth_key"`
	Device   string `json:"device"`
}

type loginResponse struct {
	Token    string `json:"token"`
	VaultKey []byte `json:"vault_key"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !readJSON(w, r, maxSmallBody, &req) {
		return
	}
	keys := []string{"ip:" + s.clientIP(r), "user:" + req.Username}
	for _, key := range keys {
		if !s.logins.allowed(key) {
			writeError(w, http.StatusTooManyRequests, "too_many_attempts")
			return
		}
	}
	u, err := s.store.user(req.Username)
	if err != nil && !errors.Is(err, errNoUser) {
		serverError(w, err)
		return
	}
	if err != nil || !authMatches(u.AuthHash, req.AuthKey) {
		for _, key := range keys {
			s.logins.fail(key)
		}
		writeError(w, http.StatusUnauthorized, "invalid_login")
		return
	}
	token, hash := newToken()
	if err := s.store.addSession(u.ID, hash, truncate(req.Device, maxDeviceName)); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{Token: token, VaultKey: u.WrappedVaultKey})
}

type tokenKey struct{}

// authed lets a request through only with a live session token.
func (s *Server) authed(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		userID, err := s.store.sessionUser(tokenHash(token))
		if errors.Is(err, errNoUser) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if err != nil {
			serverError(w, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, token)), userID)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ int64) {
	token, _ := r.Context().Value(tokenKey{}).(string)
	if err := s.store.deleteSession(tokenHash(token)); err != nil {
		serverError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type vaultKeyBody struct {
	VaultKey []byte `json:"vault_key"`
}

func (s *Server) getVaultKey(w http.ResponseWriter, _ *http.Request, userID int64) {
	s.writeVaultKey(w, userID, http.StatusOK)
}

func (s *Server) putVaultKey(w http.ResponseWriter, r *http.Request, userID int64) {
	var body vaultKeyBody
	if !readJSON(w, r, maxSmallBody, &body) {
		return
	}
	if len(body.VaultKey) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	err := s.store.setVaultKey(userID, body.VaultKey)
	if errors.Is(err, errVaultSet) {
		// Another device got there first: use its key.
		s.writeVaultKey(w, userID, http.StatusConflict)
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeVaultKey(w http.ResponseWriter, userID int64, status int) {
	key, err := s.store.vaultKey(userID)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, status, vaultKeyBody{key})
}

type pullResponse struct {
	Records  []Record `json:"records"`
	More     bool     `json:"more"`
	Revision int64    `json:"revision"`
}

func (s *Server) pullRecords(w http.ResponseWriter, r *http.Request, userID int64) {
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil || since < 0 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	records, more, revision, err := s.store.pull(userID, since)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pullResponse{records, more, revision})
}

type pushRequest struct {
	Records []Push `json:"records"`
}

func (s *Server) pushRecords(w http.ResponseWriter, r *http.Request, userID int64) {
	var req pushRequest
	if !readJSON(w, r, maxPushBody, &req) {
		return
	}
	if len(req.Records) > maxPushCount || !validPushes(req.Records) {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	result, err := s.store.push(userID, req.Records)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func validPushes(pushes []Push) bool {
	seen := map[string]bool{}
	for _, p := range pushes {
		if !validRecordID(p.ID) || seen[p.ID] || p.BaseRevision < 0 || (!p.Deleted && len(p.Data) == 0) {
			return false
		}
		seen[p.ID] = true
	}
	return true
}

func validRecordID(id string) bool {
	if id == "" || len(id) > maxRecordID {
		return false
	}
	for _, c := range id {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

// clientIP is who a login failure counts against: nginx's word for it when
// the request came through nginx on this machine.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); s.trustProxy && ip != nil && ip.IsLoopback() {
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return real
		}
	}
	return host
}

func readJSON(w http.ResponseWriter, r *http.Request, limit int64, into any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request")
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func serverError(w http.ResponseWriter, err error) {
	log.Printf("error: %v", err)
	writeError(w, http.StatusInternalServerError, "server_error")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8Start(s[max]) {
		max--
	}
	return s[:max]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// logRequests logs method, path and status: never bodies or tokens.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, recorder.status, time.Since(start).Round(time.Millisecond))
	})
}
