package provisioningapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const APIVersion = "v1"

type HandlerOptions struct {
	DB           *sql.DB
	PanelVersion string
	PublicURL    string
	Sessions     SessionCreator
	Accounts     *AccountService
}

type SessionCreator interface {
	Create(context.Context, int64) (string, time.Time, error)
}

type Handler struct {
	opts    HandlerOptions
	keys    *KeyStore
	limiter *keyLimiter
}

type contextKey string

const apiKeyContext contextKey = "provisioning-api-key"

func NewHandler(opts HandlerOptions) http.Handler {
	h := &Handler{opts: opts, keys: NewKeyStore(opts.DB), limiter: newKeyLimiter()}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r.Header.Get("X-Request-ID"))
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") && r.URL.Path != "/api/v1" {
		writeAPIError(w, http.StatusNotFound, "not_found", "resource not found", requestID, nil)
		return
	}
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || raw == "" || h.opts.DB == nil {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "a valid bearer API key is required", requestID, nil)
		return
	}
	key, err := h.keys.Authenticate(r.Context(), raw)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "a valid bearer API key is required", requestID, nil)
		return
	}
	remoteIP := directRemoteIP(r.RemoteAddr)
	status, code := 0, ""
	if remoteIP == nil || !key.AllowsIP(remoteIP) {
		status, code = http.StatusForbidden, "ip_not_allowed"
	} else if !h.limiter.Allow(key.ID, key.RateLimitPerMinute, time.Now()) {
		status, code = http.StatusTooManyRequests, "rate_limited"
	}
	auditID := h.startAudit(r.Context(), key, requestID, r.Method, normalizedRoute(r.URL.Path), remoteIP)
	if status != 0 {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "60")
		}
		writeAPIError(w, status, code, map[bool]string{true: "request rate limit exceeded", false: "remote address is not permitted"}[status == http.StatusTooManyRequests], requestID, nil)
		h.finishAudit(r.Context(), auditID, status, code)
		return
	}
	recorder := &apiRecorder{ResponseWriter: w, status: http.StatusOK}
	h.serveIdempotent(recorder, r.WithContext(context.WithValue(r.Context(), apiKeyContext, key)), key, requestID)
	h.finishAudit(r.Context(), auditID, recorder.status, recorder.errorCode)
}

func (h *Handler) serveIdempotent(w *apiRecorder, r *http.Request, key APIKey, requestID string) {
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" || (r.Method != http.MethodPost && r.Method != http.MethodDelete) || strings.HasSuffix(r.URL.Path, "/login-link") {
		h.serveAuthenticated(w, r, requestID)
		return
	}
	if len(idempotencyKey) > 128 || strings.ContainsAny(idempotencyKey, "\r\n") {
		writeAPIError(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must contain 1-128 characters", requestID, nil)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeAPIError(w, 400, "invalid_json", "could not read request body", requestID, nil)
		return
	}
	digest := sha256.Sum256(append([]byte(r.Method+"\n"+r.URL.RequestURI()+"\n"), body...))
	tx, err := h.opts.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeAPIError(w, 500, "internal_error", "could not establish idempotency", requestID, nil)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,20))`, fmt.Sprintf("%d:%s", key.ID, idempotencyKey)); err != nil {
		writeAPIError(w, 500, "internal_error", "could not establish idempotency", requestID, nil)
		return
	}
	var method, path string
	var storedHash []byte
	var responseStatus sql.NullInt64
	var responseBody []byte
	err = tx.QueryRowContext(r.Context(), `SELECT method,path,request_hash,response_status,response_body::text FROM api_idempotency_records WHERE api_key_id=$1 AND idempotency_key=$2 AND expires_at>now() FOR UPDATE`, key.ID, idempotencyKey).Scan(&method, &path, &storedHash, &responseStatus, &responseBody)
	if err == nil {
		if method != r.Method || path != r.URL.RequestURI() || subtle.ConstantTimeCompare(storedHash, digest[:]) != 1 {
			writeAPIError(w, 409, "idempotency_conflict", "Idempotency-Key was already used for a different request", requestID, nil)
			return
		}
		if responseStatus.Valid && len(responseBody) > 0 {
			w.Header().Set("Idempotency-Replayed", "true")
			w.WriteHeader(int(responseStatus.Int64))
			_, _ = w.Write(responseBody)
			_ = tx.Commit()
			return
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeAPIError(w, 500, "internal_error", "could not read idempotency record", requestID, nil)
		return
	} else {
		if _, err = tx.ExecContext(r.Context(), `INSERT INTO api_idempotency_records(api_key_id,idempotency_key,method,path,request_hash) VALUES($1,$2,$3,$4,$5)`, key.ID, idempotencyKey, r.Method, r.URL.RequestURI(), digest[:]); err != nil {
			writeAPIError(w, 500, "internal_error", "could not persist idempotency record", requestID, nil)
			return
		}
	}
	buffer := newBufferedResponse()
	r.Body = io.NopCloser(bytes.NewReader(body))
	bufferRecorder := &apiRecorder{ResponseWriter: buffer, status: http.StatusOK}
	h.serveAuthenticated(bufferRecorder, r, requestID)
	var jsonBody any
	if json.Unmarshal(buffer.body.Bytes(), &jsonBody) != nil {
		jsonBody = map[string]any{"error": map[string]any{"code": "internal_error", "message": "non-JSON API response"}}
	}
	encoded, _ := json.Marshal(jsonBody)
	if _, err = tx.ExecContext(r.Context(), `UPDATE api_idempotency_records SET response_status=$3,response_body=$4::jsonb WHERE api_key_id=$1 AND idempotency_key=$2`, key.ID, idempotencyKey, bufferRecorder.status, encoded); err != nil {
		writeAPIError(w, 500, "internal_error", "could not complete idempotency record", requestID, nil)
		return
	}
	if err = tx.Commit(); err != nil {
		writeAPIError(w, 500, "internal_error", "could not complete idempotency record", requestID, nil)
		return
	}
	copyHeaders(w.Header(), buffer.header)
	w.status = bufferRecorder.status
	w.errorCode = bufferRecorder.errorCode
	w.WriteHeader(bufferRecorder.status)
	_, _ = w.Write(buffer.body.Bytes())
}

func (h *Handler) serveAuthenticated(w *apiRecorder, r *http.Request, requestID string) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case path == "/api/v1/ping" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"api_version": APIVersion, "panel_version": h.opts.PanelVersion, "health": "ok"})
	case path == "/api/v1/providers" && r.Method == http.MethodGet:
		h.handleProviders(w, r, requestID)
	case path == "/api/v1/plans" && r.Method == http.MethodGet:
		h.handlePlans(w, r, requestID)
	case path == "/api/v1/accounts" && r.Method == http.MethodPost:
		h.handleCreateAccount(w, r, requestID)
	case strings.HasPrefix(path, "/api/v1/accounts/"):
		h.handleAccount(w, r, strings.TrimPrefix(path, "/api/v1/accounts/"), requestID)
	default:
		writeAPIError(w, http.StatusNotFound, "not_found", "resource not found", requestID, nil)
	}
}

type apiRecorder struct {
	http.ResponseWriter
	status    int
	errorCode string
}

func (r *apiRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: 200}
}
func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(status int)      { b.status = status }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

type apiErrorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		Details   any    `json:"details,omitempty"`
	} `json:"error"`
}

func writeAPIError(w http.ResponseWriter, status int, code, message, requestID string, details any) {
	if recorder, ok := w.(*apiRecorder); ok {
		recorder.errorCode = code
	}
	var body apiErrorEnvelope
	body.Error.Code, body.Error.Message, body.Error.RequestID, body.Error.Details = code, message, requestID, details
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeStrictJSON(reader io.Reader, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request must contain one JSON value")
		}
		return err
	}
	return nil
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func requestID(value string) string {
	if requestIDPattern.MatchString(value) {
		return value
	}
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return "req_" + base64.RawURLEncoding.EncodeToString(b)
}
func normalizedRoute(path string) string {
	if strings.HasPrefix(path, "/api/v1/accounts/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/accounts/"), "/")
		if len(parts) > 1 {
			return "/api/v1/accounts/{ref}/" + parts[1]
		}
		return "/api/v1/accounts/{ref}"
	}
	return strings.TrimSuffix(path, "/")
}
func directRemoteIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

type limiterBucket struct {
	window time.Time
	count  int
}
type keyLimiter struct {
	mu      sync.Mutex
	buckets map[int64]limiterBucket
}

func newKeyLimiter() *keyLimiter { return &keyLimiter{buckets: make(map[int64]limiterBucket)} }
func (l *keyLimiter) Allow(id int64, limit int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 {
		limit = 120
	}
	b := l.buckets[id]
	if b.window.IsZero() || now.Sub(b.window) >= time.Minute {
		b = limiterBucket{window: now}
	}
	if b.count >= limit {
		l.buckets[id] = b
		return false
	}
	b.count++
	l.buckets[id] = b
	return true
}

func (h *Handler) startAudit(ctx context.Context, key APIKey, requestID, method, route string, ip net.IP) int64 {
	if h.opts.DB == nil {
		return 0
	}
	metadata, _ := json.Marshal(map[string]any{"request_id": requestID, "method": method, "route": route, "remote_ip": ip.String(), "status": 0})
	var id int64
	_ = h.opts.DB.QueryRowContext(ctx, `INSERT INTO audit_events(actor_label,action,target_type,metadata) VALUES($1,'api.request','api_request',$2) RETURNING id`, "api-key:"+key.Name+":"+key.Prefix, metadata).Scan(&id)
	return id
}
func (h *Handler) finishAudit(ctx context.Context, id int64, status int, code string) {
	if id == 0 {
		return
	}
	_, _ = h.opts.DB.ExecContext(ctx, `UPDATE audit_events SET metadata=metadata||jsonb_build_object('status',$2::int,'error_code',$3::text) WHERE id=$1`, id, status, code)
}
