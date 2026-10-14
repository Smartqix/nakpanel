package ops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRemovalMailboxPrincipalIsExactAndPrivate(t *testing.T) {
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "admin" || password != "test-secret" {
			t.Error("missing private authentication")
		}
		if r.URL.Path != "/api/principal/box@addon.test" || r.URL.RawQuery != "" {
			t.Errorf("unsafe principal target %s", r.URL.String())
		}
		if r.Method == http.MethodDelete {
			deleted = true
			w.Write([]byte(`{"data":null}`))
			return
		}
		if deleted {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(`{"data":{"name":"box@addon.test","type":"individual"}}`))
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "admin-secret")
	os.WriteFile(secret, []byte("test-secret"), 0600)
	runner := &teardownRunner{outputs: map[string][]byte{"stalwart-mail": []byte("Stalwart Mail Server v0.11.8")}}
	p := NewMailProvisioner(MailProvisionerOptions{ManagementURL: server.URL, AdminSecretPath: secret, Runner: runner})
	if err := p.removeMailboxPrincipal(context.Background(), "box@addon.test"); err != nil || !deleted {
		t.Fatalf("principal cleanup: %v", err)
	}
	if err := p.removeMailboxPrincipal(context.Background(), "box@addon.test"); err != nil {
		t.Fatal("absent replay", err)
	}
}

func TestRemovalMailboxRejectsVersionRedirectAndNonIndividual(t *testing.T) {
	for _, mode := range []string{"version", "redirect", "group", "remote"} {
		t.Run(mode, func(t *testing.T) {
			deleted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deleted = true
				}
				if mode == "redirect" {
					http.Redirect(w, r, "http://example.test/", 302)
					return
				}
				w.Write([]byte(`{"data":{"name":"box@addon.test","type":"group"}}`))
			}))
			defer server.Close()
			secret := filepath.Join(t.TempDir(), "admin-secret")
			os.WriteFile(secret, []byte("test-secret"), 0600)
			version := "v0.11.8"
			if mode == "version" {
				version = "v0.12.0"
			}
			url := server.URL
			if mode == "remote" {
				url = "http://example.test"
			}
			p := NewMailProvisioner(MailProvisionerOptions{ManagementURL: url, AdminSecretPath: secret, Runner: &teardownRunner{outputs: map[string][]byte{"stalwart-mail": []byte(version)}}})
			if err := p.removeMailboxPrincipal(context.Background(), "box@addon.test"); err == nil || deleted {
				t.Fatalf("unsafe mailbox deletion mode %s: %v", mode, err)
			}
		})
	}
}
