package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// S3-compatible destination speaking the minimal API subset nakpanel needs:
// PutObject, GetObject, DeleteObject, ListObjectsV2, and multipart uploads
// for large archives. Path-style addressing is the default because most
// self-hosted S3-compatible stores (MinIO, Garage, Ceph RGW) expect it.

const (
	// s3MultipartThreshold is the object size above which multipart upload is
	// used; also used when the size is unknown.
	s3MultipartThreshold = int64(1) << 30 // 1 GiB
	// s3PartSize bounds worker memory: one part buffer per upload.
	s3PartSize = int64(64) << 20 // 64 MiB
)

type s3Settings struct {
	Endpoint       string `json:"endpoint"`
	Region         string `json:"region"`
	Bucket         string `json:"bucket"`
	Prefix         string `json:"prefix"`
	ForcePathStyle *bool  `json:"force_path_style,omitempty"`
}

type s3Credential struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type s3Destination struct {
	endpoint  *url.URL
	region    string
	bucket    string
	prefix    string
	pathStyle bool
	creds     s3Credential
	client    *http.Client
	now       func() time.Time
}

func newS3Destination(settings json.RawMessage, credential []byte) (Destination, error) {
	var cfg s3Settings
	dec := json.NewDecoder(bytes.NewReader(settings))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("backup: s3 settings: %w", err)
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, errors.New("backup: s3 endpoint is required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("backup: s3 endpoint must be an http(s) URL")
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("backup: s3 bucket is required")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	var creds s3Credential
	credDec := json.NewDecoder(bytes.NewReader(credential))
	credDec.DisallowUnknownFields()
	if err := credDec.Decode(&creds); err != nil {
		return nil, fmt.Errorf("backup: s3 credential: %w", err)
	}
	if creds.AccessKey == "" || creds.SecretKey == "" {
		return nil, errors.New("backup: s3 credential requires access_key and secret_key")
	}
	prefix := strings.Trim(strings.TrimSpace(cfg.Prefix), "/")
	if prefix != "" {
		prefix += "/"
	}
	pathStyle := true
	if cfg.ForcePathStyle != nil {
		pathStyle = *cfg.ForcePathStyle
	}
	return &s3Destination{
		endpoint:  parsed,
		region:    region,
		bucket:    strings.TrimSpace(cfg.Bucket),
		prefix:    prefix,
		pathStyle: pathStyle,
		creds:     creds,
		client:    &http.Client{Timeout: 0},
		now:       time.Now,
	}, nil
}

func (d *s3Destination) objectURL(key string, query url.Values) *url.URL {
	u := *d.endpoint
	var path string
	if d.pathStyle {
		path = "/" + d.bucket
		if key != "" {
			path += "/" + key
		}
	} else {
		u.Host = d.bucket + "." + u.Host
		path = "/"
		if key != "" {
			path += key
		}
	}
	u.Path = path
	u.RawPath = uriEncode(path, false)
	if query != nil {
		u.RawQuery = query.Encode()
	}
	return &u
}

func (d *s3Destination) do(ctx context.Context, method string, key string, query url.Values, body io.Reader, size int64, payloadHash, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, d.objectURL(key, query).String(), body)
	if err != nil {
		return nil, err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	signV4(req, d.creds.AccessKey, d.creds.SecretKey, d.region, payloadHash, d.now())
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, fmt.Errorf("backup: s3 %s %s: %s: %s", method, key, resp.Status, strings.TrimSpace(string(detail)))
	}
	return resp, nil
}

func (d *s3Destination) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if err := validateObjectName(name); err != nil {
		return err
	}
	key := d.prefix + name
	if size >= 0 && size <= s3MultipartThreshold {
		resp, err := d.do(ctx, http.MethodPut, key, nil, r, size, unsignedPayload, "application/octet-stream")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	return d.putMultipart(ctx, key, r)
}

type initiateMultipartResult struct {
	UploadID string `xml:"UploadId"`
}

type completedPart struct {
	XMLName    xml.Name `xml:"Part"`
	PartNumber int      `xml:"PartNumber"`
	ETag       string   `xml:"ETag"`
}

type completeMultipartUpload struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []completedPart `xml:"Part"`
}

func (d *s3Destination) putMultipart(ctx context.Context, key string, r io.Reader) (err error) {
	initQuery := url.Values{"uploads": []string{""}}
	resp, err := d.do(ctx, http.MethodPost, key, initQuery, nil, 0, sha256Hex(nil), "application/octet-stream")
	if err != nil {
		return err
	}
	var initiated initiateMultipartResult
	decodeErr := xml.NewDecoder(resp.Body).Decode(&initiated)
	resp.Body.Close()
	if decodeErr != nil {
		return fmt.Errorf("backup: s3 initiate multipart: %w", decodeErr)
	}
	if initiated.UploadID == "" {
		return errors.New("backup: s3 initiate multipart returned no upload id")
	}
	defer func() {
		if err != nil {
			// Detached from ctx (the upload may have failed because ctx died)
			// but bounded: an unreachable endpoint must not hang the worker,
			// which holds the single backup queue slot.
			abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			abortQuery := url.Values{"uploadId": []string{initiated.UploadID}}
			if abortResp, abortErr := d.do(abortCtx, http.MethodDelete, key, abortQuery, nil, 0, sha256Hex(nil), ""); abortErr == nil {
				abortResp.Body.Close()
			}
		}
	}()

	buf := make([]byte, s3PartSize)
	var parts []completedPart
	for partNumber := 1; ; partNumber++ {
		n, readErr := io.ReadFull(r, buf)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		partQuery := url.Values{
			"partNumber": []string{fmt.Sprintf("%d", partNumber)},
			"uploadId":   []string{initiated.UploadID},
		}
		partResp, putErr := d.do(ctx, http.MethodPut, key, partQuery, bytes.NewReader(buf[:n]), int64(n), unsignedPayload, "application/octet-stream")
		if putErr != nil {
			return putErr
		}
		etag := partResp.Header.Get("ETag")
		partResp.Body.Close()
		if etag == "" {
			return errors.New("backup: s3 part upload returned no etag")
		}
		parts = append(parts, completedPart{PartNumber: partNumber, ETag: etag})
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	if len(parts) == 0 {
		// S3 requires at least one part; upload an empty one.
		partQuery := url.Values{"partNumber": []string{"1"}, "uploadId": []string{initiated.UploadID}}
		partResp, putErr := d.do(ctx, http.MethodPut, key, partQuery, bytes.NewReader(nil), 0, unsignedPayload, "application/octet-stream")
		if putErr != nil {
			return putErr
		}
		etag := partResp.Header.Get("ETag")
		partResp.Body.Close()
		parts = append(parts, completedPart{PartNumber: 1, ETag: etag})
	}

	payload, marshalErr := xml.Marshal(completeMultipartUpload{Parts: parts})
	if marshalErr != nil {
		return marshalErr
	}
	completeQuery := url.Values{"uploadId": []string{initiated.UploadID}}
	completeResp, err := d.do(ctx, http.MethodPost, key, completeQuery, bytes.NewReader(payload), int64(len(payload)), sha256Hex(payload), "application/xml")
	if err != nil {
		return err
	}
	// CompleteMultipartUpload can return 200 with an error document.
	completeBody, _ := io.ReadAll(io.LimitReader(completeResp.Body, 1<<20))
	completeResp.Body.Close()
	if bytes.Contains(completeBody, []byte("<Error>")) {
		return fmt.Errorf("backup: s3 complete multipart failed: %s", strings.TrimSpace(string(completeBody)))
	}
	return nil
}

func (d *s3Destination) Open(ctx context.Context, name string) (io.ReadCloser, int64, error) {
	if err := validateObjectName(name); err != nil {
		return nil, 0, err
	}
	resp, err := d.do(ctx, http.MethodGet, d.prefix+name, nil, nil, 0, sha256Hex(nil), "")
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

type listBucketResult struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string `xml:"Key"`
		Size         int64  `xml:"Size"`
		LastModified string `xml:"LastModified"`
	} `xml:"Contents"`
}

func (d *s3Destination) List(ctx context.Context) ([]ObjectInfo, error) {
	var result []ObjectInfo
	continuation := ""
	for {
		query := url.Values{"list-type": []string{"2"}}
		if d.prefix != "" {
			query.Set("prefix", d.prefix)
		}
		if continuation != "" {
			query.Set("continuation-token", continuation)
		}
		resp, err := d.do(ctx, http.MethodGet, "", query, nil, 0, sha256Hex(nil), "")
		if err != nil {
			return nil, err
		}
		var page listBucketResult
		decodeErr := xml.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("backup: s3 list: %w", decodeErr)
		}
		for _, item := range page.Contents {
			key := strings.TrimPrefix(item.Key, d.prefix)
			if key == "" || strings.Contains(key, "/") {
				continue
			}
			modTime, _ := time.Parse(time.RFC3339, item.LastModified)
			result = append(result, ObjectInfo{Name: key, Size: item.Size, ModTime: modTime})
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return result, nil
		}
		continuation = page.NextContinuationToken
	}
}

func (d *s3Destination) Delete(ctx context.Context, name string) error {
	if err := validateObjectName(name); err != nil {
		return err
	}
	resp, err := d.do(ctx, http.MethodDelete, d.prefix+name, nil, nil, 0, sha256Hex(nil), "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (d *s3Destination) Probe(ctx context.Context) error {
	return probeDestination(ctx, d)
}
