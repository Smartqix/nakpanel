package panelhttp

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const maxUserFacingErrorBytes = 4 << 10

var userFacingErrorTemplate = template.Must(template.New("error-page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} · nakpanel</title>
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body class="np-app np-auth antialiased" data-np-error-page>
  <main class="np-error-stage">
    <section class="np-error-card" aria-labelledby="error-title">
      <div class="np-brand"><span class="np-brand-mark" aria-hidden="true">n</span><span>nakpanel</span></div>
      <span class="np-error-code">HTTP {{.Status}}</span>
      <h1 id="error-title">{{.Title}}</h1>
      <p>{{.Message}}</p>
      <div class="np-error-actions">
        <button type="button" class="np-secondary-button" data-np-error-back>Go back</button>
        <a class="np-primary-link" href="{{.ReturnPath}}">Return to {{.ReturnLabel}}</a>
      </div>
    </section>
  </main>
  <script defer src="/assets/app.js"></script>
</body>
</html>`))

type capturedErrorWriter struct {
	target    http.ResponseWriter
	status    int
	wroteHead bool
	capturing bool
	body      bytes.Buffer
}

func (w *capturedErrorWriter) Header() http.Header { return w.target.Header() }

func (w *capturedErrorWriter) WriteHeader(status int) {
	if w.wroteHead {
		return
	}
	w.wroteHead = true
	w.status = status
	if w.Header().Get("X-Nakpanel-Complete-Error-Page") == "1" {
		w.Header().Del("X-Nakpanel-Complete-Error-Page")
		w.target.WriteHeader(status)
		return
	}
	if status >= http.StatusBadRequest {
		if status < http.StatusInternalServerError && isJSONContentType(w.Header().Get("Content-Type")) {
			w.target.WriteHeader(status)
			return
		}
		w.capturing = true
		return
	}
	w.target.WriteHeader(status)
}

func (w *capturedErrorWriter) Write(body []byte) (int, error) {
	if !w.wroteHead {
		w.WriteHeader(http.StatusOK)
	}
	if w.capturing {
		remaining := maxUserFacingErrorBytes + 1 - w.body.Len()
		if remaining > 0 {
			if remaining < len(body) {
				_, _ = w.body.Write(body[:remaining])
			} else {
				_, _ = w.body.Write(body)
			}
		}
		return len(body), nil
	}
	return w.target.Write(body)
}

func (w *capturedErrorWriter) Flush() {
	if !w.wroteHead {
		w.WriteHeader(http.StatusOK)
	}
	if w.capturing {
		return
	}
	if flusher, ok := w.target.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *capturedErrorWriter) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wroteHead {
		w.WriteHeader(http.StatusOK)
	}
	if w.capturing {
		var copied int64
		buffer := make([]byte, 32<<10)
		for {
			read, err := reader.Read(buffer)
			if read > 0 {
				_, _ = w.Write(buffer[:read])
				copied += int64(read)
			}
			if err == io.EOF {
				return copied, nil
			}
			if err != nil {
				return copied, err
			}
		}
	}
	return io.Copy(w.target, reader)
}

func (w *capturedErrorWriter) Unwrap() http.ResponseWriter { return w.target }

func userFacingErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured := &capturedErrorWriter{target: w}
		defer func() {
			if recovered := recover(); recovered != nil {
				if captured.wroteHead && !captured.capturing {
					panic(recovered)
				}
				log.Printf("nakpanel-http: recovered panic serving %s %s", r.Method, r.URL.EscapedPath())
				clearUserFacingHeaders(captured.Header())
				captured.status = http.StatusInternalServerError
				captured.wroteHead = true
				captured.capturing = true
				captured.body.Reset()
				captured.finish(r)
				return
			}
			if captured.capturing {
				captured.finish(r)
			}
		}()
		next.ServeHTTP(captured, r)
	})
}

func (w *capturedErrorWriter) finish(r *http.Request) {
	sourceJSON := isJSONContentType(w.Header().Get("Content-Type"))
	if sourceJSON && w.status < http.StatusInternalServerError {
		w.target.WriteHeader(w.status)
		_, _ = w.target.Write(w.body.Bytes())
		return
	}
	clearUserFacingHeaders(w.Header())
	rawMessage := w.body.String()
	field := userFacingErrorField(rawMessage)
	title, message := userFacingErrorCopy(w.status, rawMessage)
	w.Header().Set("Cache-Control", "no-store")
	if sourceJSON || wantsJSONError(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.target.WriteHeader(w.status)
		_ = json.NewEncoder(w.target).Encode(map[string]any{
			"ok": false, "status": w.status, "title": title, "error": message,
			"field": field,
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.target.WriteHeader(w.status)
	_ = userFacingErrorTemplate.Execute(w.target, map[string]any{
		"Status": w.status, "Title": title, "Message": message,
		"ReturnPath": safeErrorReturnPath(r), "ReturnLabel": safeErrorReturnLabel(r),
	})
}

func isJSONContentType(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "application/json")
}

func clearUserFacingHeaders(header http.Header) {
	for _, name := range []string{"Content-Disposition", "Content-Encoding", "Content-Length", "Content-Type", "ETag", "Location", "Refresh"} {
		header.Del(name)
	}
}

func userFacingErrorField(message string) string {
	fields := []struct {
		contract string
		form     string
	}{
		{"php_memory_limit_mb", "site_php_memory"},
		{"fpm_max_children", "site_fpm_children"},
		{"fpm_max_requests", "site_fpm_requests"},
		{"fpm_idle_timeout_seconds", "site_fpm_idle"},
		{"request_terminate_timeout_seconds", "site_fpm_terminate"},
		{"max_execution_seconds", "site_php_execution"},
		{"max_input_seconds", "site_php_input"},
		{"post_max_mb", "site_php_post"},
		{"upload_max_mb", "site_php_upload"},
		{"opcache_memory_mb", "site_php_opcache_memory"},
		{"request_body_limit_mb", "site_body_limit"},
		{"request_rate_per_second", "site_request_rate"},
		{"request_burst", "site_request_burst"},
		{"max_connections", "site_max_connections"},
		{"cache_ttl_seconds", "site_cache_ttl"},
		{"connect_timeout_seconds", "site_connect_timeout"},
		{"read_timeout_seconds", "site_read_timeout"},
		{"PHP URL fopen", "site_php_url_fopen"},
		{"PHP error display", "site_php_display_errors"},
		{"PHP process execution", "site_php_exec"},
		{"OPcache", "site_php_opcache"},
	}
	for _, field := range fields {
		if strings.Contains(message, field.contract) {
			return field.form
		}
	}
	if strings.Contains(message, "PHP ") && (strings.Contains(message, "not allowed by this subscription") || strings.Contains(message, "not installed on the server")) {
		return "desired_php_version"
	}
	return ""
}

func wantsJSONError(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Nakpanel-SPA")), "true") ||
		strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

func userFacingErrorCopy(status int, raw string) (string, string) {
	message := strings.TrimSpace(raw)
	if len(message) > maxUserFacingErrorBytes {
		message = ""
	}
	switch status {
	case http.StatusBadRequest:
		if strings.Contains(message, "PHP ") && strings.Contains(message, "not installed on the server") {
			return "PHP runtime unavailable", "The selected PHP version is not available on this server. Choose one of the listed versions."
		}
		if strings.Contains(message, "PHP ") && strings.Contains(message, "not allowed by this subscription") {
			return "PHP runtime unavailable", "The selected PHP version is not available for this subscription. Choose one of the listed versions."
		}
		if strings.Contains(message, "exceeds or removes the subscription ceiling") {
			return "Check the form", userFacingFieldLabel(userFacingErrorField(message)) + " cannot be higher than the limit allowed for this subscription."
		}
		if strings.Contains(message, "not delegated by the subscription") {
			return "Setting unavailable", userFacingFieldLabel(userFacingErrorField(message)) + " is not enabled for this subscription."
		}
		if message == "" {
			message = "Review the submitted values and try again."
		}
		return "Unable to complete request", message
	case http.StatusUnauthorized:
		return "Sign in required", "Your session is missing or has expired. Sign in and try again."
	case http.StatusForbidden:
		return "Action not allowed", "You do not have permission to perform this action."
	case http.StatusNotFound:
		return "Page not found", "The requested page or resource could not be found."
	case http.StatusMethodNotAllowed:
		return "Method not allowed", "This action is not available for the requested method."
	case http.StatusConflict:
		if message == "" {
			message = "The resource changed before this action could be completed. Refresh and try again."
		}
		return "Request conflict", message
	case http.StatusRequestEntityTooLarge:
		return "Request too large", "The submitted data exceeds the allowed size."
	case http.StatusTooManyRequests:
		return "Too many requests", "Wait a moment before trying this action again."
	default:
		if status >= http.StatusInternalServerError {
			return "Something went wrong", "Nakpanel could not complete this request. Try again, or check Activity if the problem continues."
		}
		if message == "" {
			message = http.StatusText(status)
		}
		return http.StatusText(status), message
	}
}

func userFacingFieldLabel(field string) string {
	labels := map[string]string{
		"site_php_memory":         "PHP memory",
		"site_fpm_children":       "FPM children",
		"site_fpm_requests":       "FPM requests",
		"site_fpm_idle":           "FPM idle timeout",
		"site_fpm_terminate":      "PHP request timeout",
		"site_php_execution":      "PHP execution time",
		"site_php_input":          "PHP input time",
		"site_php_post":           "PHP POST size",
		"site_php_upload":         "PHP upload size",
		"site_php_opcache_memory": "OPcache memory",
		"site_php_url_fopen":      "URL fopen",
		"site_php_display_errors": "PHP error display",
		"site_php_exec":           "PHP process execution",
		"site_php_opcache":        "OPcache",
		"desired_php_version":     "PHP version",
	}
	if label := labels[field]; label != "" {
		return label
	}
	return "This setting"
}

func safeErrorReturnPath(r *http.Request) string {
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return "/dashboard"
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
		return "/dashboard"
	}
	if parsed.Host != "" && !strings.EqualFold(parsed.Host, r.Host) {
		return "/dashboard"
	}
	return parsed.EscapedPath() + querySuffix(parsed.RawQuery)
}

func safeErrorReturnLabel(r *http.Request) string {
	if safeErrorReturnPath(r) == "/dashboard" {
		return "dashboard"
	}
	return "previous page"
}

func querySuffix(raw string) string {
	if raw == "" {
		return ""
	}
	return "?" + raw
}
