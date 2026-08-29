package backup

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Known-answer tests from the AWS "Signature Calculations for the
// Authorization Header" S3 examples (access key AKIAIOSFODNN7EXAMPLE).
const (
	katAccessKey = "AKIAIOSFODNN7EXAMPLE"
	katSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

var katTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func TestSignV4GetObjectKAT(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-9")
	emptyHash := sha256Hex(nil)
	signV4(req, katAccessKey, katSecretKey, "us-east-1", emptyHash, katTime)
	auth := req.Header.Get("Authorization")
	wantSig := "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if !strings.Contains(auth, "Signature="+wantSig) {
		t.Fatalf("GET signature mismatch:\n%s", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("unexpected signed headers: %s", auth)
	}
}

func TestSignV4ListObjectsKAT(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	if err != nil {
		t.Fatal(err)
	}
	signV4(req, katAccessKey, katSecretKey, "us-east-1", sha256Hex(nil), katTime)
	wantSig := "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
	if auth := req.Header.Get("Authorization"); !strings.Contains(auth, "Signature="+wantSig) {
		t.Fatalf("list signature mismatch:\n%s", auth)
	}
}

func TestURIEncode(t *testing.T) {
	cases := map[string]string{
		"simple.txt":    "simple.txt",
		"a b":           "a%20b",
		"a/b":           "a/b",
		"pre fix/x~y_z": "pre%20fix/x~y_z",
	}
	for in, want := range cases {
		if got := uriEncode(in, false); got != want {
			t.Fatalf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := uriEncode("a/b", true); got != "a%2Fb" {
		t.Fatalf("uriEncode slash = %q", got)
	}
}
