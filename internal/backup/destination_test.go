package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestLocalDestinationRoundTrip(t *testing.T) {
	dir := t.TempDir()
	settings, _ := json.Marshal(map[string]string{"dir": dir})
	dest, err := NewDestination("local", settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload := []byte("hello local destination")
	if err := dest.Put(ctx, "a.nkbk", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	rc, size, err := dest.Open(ctx, "a.nkbk")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) || size != int64(len(payload)) {
		t.Fatal("local round trip mismatch")
	}
	items, err := dest.List(ctx)
	if err != nil || len(items) != 1 || items[0].Name != "a.nkbk" {
		t.Fatalf("list: %v %+v", err, items)
	}
	if err := dest.Probe(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := dest.Delete(ctx, "a.nkbk"); err != nil {
		t.Fatal(err)
	}
	if items, _ := dest.List(ctx); len(items) != 0 {
		t.Fatal("expected empty list after delete")
	}
	if err := dest.Put(ctx, "../evil", bytes.NewReader(payload), 4); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

// fakeS3 is a minimal in-memory S3-compatible server that also validates
// every request's SigV4 signature by recomputation.
type fakeS3 struct {
	mu       sync.Mutex
	objects  map[string][]byte
	uploads  map[string]map[int][]byte
	nextID   int
	access   string
	secret   string
	region   string
	failPuts int
	t        *testing.T
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if err := f.validateSignatureFull(r, body); err != nil {
		f.t.Errorf("signature validation: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Path-style addressing: /<bucket>/<key>.
	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	if parts[0] != "backups" {
		http.Error(w, "wrong bucket", http.StatusNotFound)
		return
	}
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodPost && query.Has("uploads"):
		f.nextID++
		id := fmt.Sprintf("upload-%d", f.nextID)
		f.uploads[id] = map[int][]byte{}
		fmt.Fprintf(w, `<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>`, id)
	case r.Method == http.MethodPut && query.Get("uploadId") != "":
		id := query.Get("uploadId")
		parts, ok := f.uploads[id]
		if !ok {
			http.Error(w, "no such upload", http.StatusNotFound)
			return
		}
		var partNumber int
		fmt.Sscanf(query.Get("partNumber"), "%d", &partNumber)
		parts[partNumber] = body
		w.Header().Set("ETag", fmt.Sprintf("\"etag-%d\"", partNumber))
	case r.Method == http.MethodPost && query.Get("uploadId") != "":
		id := query.Get("uploadId")
		parts, ok := f.uploads[id]
		if !ok {
			http.Error(w, "no such upload", http.StatusNotFound)
			return
		}
		var doc completeMultipartUpload
		if err := xml.Unmarshal(body, &doc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var assembled []byte
		for i := 1; i <= len(parts); i++ {
			assembled = append(assembled, parts[i]...)
		}
		f.objects[key] = assembled
		delete(f.uploads, id)
		fmt.Fprint(w, `<CompleteMultipartUploadResult></CompleteMultipartUploadResult>`)
	case r.Method == http.MethodDelete && query.Get("uploadId") != "":
		delete(f.uploads, query.Get("uploadId"))
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut:
		if f.failPuts > 0 {
			f.failPuts--
			http.Error(w, "<Error>induced failure</Error>", http.StatusInternalServerError)
			return
		}
		f.objects[key] = body
	case r.Method == http.MethodGet && query.Get("list-type") == "2":
		prefix := query.Get("prefix")
		var sb strings.Builder
		sb.WriteString("<ListBucketResult><IsTruncated>false</IsTruncated>")
		for name, data := range f.objects {
			if prefix == "" || strings.HasPrefix(name, prefix) {
				fmt.Fprintf(&sb, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>2026-08-26T00:00:00Z</LastModified></Contents>", name, len(data))
			}
		}
		sb.WriteString("</ListBucketResult>")
		io.WriteString(w, sb.String())
	case r.Method == http.MethodGet:
		data, ok := f.objects[key]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
	case r.Method == http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unhandled", http.StatusBadRequest)
	}
}

func (f *fakeS3) validateSignatureFull(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return fmt.Errorf("missing sigv4 authorization")
	}
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash != unsignedPayload && payloadHash != sha256Hex(body) {
		return fmt.Errorf("payload hash mismatch")
	}
	return nil
}

func newFakeS3Destination(t *testing.T, fake *fakeS3) (Destination, *httptest.Server) {
	server := httptest.NewServer(fake)
	settings, _ := json.Marshal(map[string]any{
		"endpoint": server.URL,
		"region":   fake.region,
		"bucket":   "backups",
		"prefix":   "nak",
	})
	credential, _ := json.Marshal(map[string]string{"access_key": fake.access, "secret_key": fake.secret})
	dest, err := NewDestination("s3", settings, credential)
	if err != nil {
		t.Fatal(err)
	}
	return dest, server
}

func TestS3DestinationRoundTrip(t *testing.T) {
	fake := &fakeS3{objects: map[string][]byte{}, uploads: map[string]map[int][]byte{}, access: "AK", secret: "SK", region: "us-east-1", t: t}
	dest, server := newFakeS3Destination(t, fake)
	defer server.Close()

	ctx := context.Background()
	payload := bytes.Repeat([]byte("s3-data-"), 1024)
	if err := dest.Put(ctx, "arch.nkbk", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	rc, _, err := dest.Open(ctx, "arch.nkbk")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatal("s3 round trip mismatch")
	}
	items, err := dest.List(ctx)
	if err != nil || len(items) != 1 || items[0].Name != "arch.nkbk" {
		t.Fatalf("list: %v %+v", err, items)
	}
	if err := dest.Probe(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := dest.Delete(ctx, "arch.nkbk"); err != nil {
		t.Fatal(err)
	}
	if items, _ := dest.List(ctx); len(items) != 0 {
		t.Fatalf("expected empty list, got %+v", items)
	}
}

func TestS3DestinationMultipart(t *testing.T) {
	fake := &fakeS3{objects: map[string][]byte{}, uploads: map[string]map[int][]byte{}, access: "AK", secret: "SK", region: "us-east-1", t: t}
	dest, server := newFakeS3Destination(t, fake)
	defer server.Close()

	ctx := context.Background()
	payload := bytes.Repeat([]byte("m"), 3*1024)
	// Unknown size (-1) forces the multipart path regardless of threshold.
	if err := dest.Put(ctx, "big.nkbk", bytes.NewReader(payload), -1); err != nil {
		t.Fatal(err)
	}
	rc, _, err := dest.Open(ctx, "big.nkbk")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("multipart round trip mismatch: got %d bytes want %d", len(got), len(payload))
	}
	if len(fake.uploads) != 0 {
		t.Fatal("upload state leaked")
	}
}
