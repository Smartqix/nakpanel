package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nakroteck/nakpanel/internal/config"
)

func runSecretKey(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("usage: panelctl secret-key init [--path /etc/nakpanel/secret-keys.json]")
	}
	set := flag.NewFlagSet("secret-key init", flag.ContinueOnError)
	set.SetOutput(stderr)
	path := set.String("path", config.DefaultSecretKeyFile, "absolute secret key file path")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("secret-key init does not accept positional arguments")
	}
	clean := filepath.Clean(strings.TrimSpace(*path))
	if !filepath.IsAbs(clean) || clean != strings.TrimSpace(*path) {
		return errors.New("secret key path must be absolute and clean")
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
		return fmt.Errorf("create secret key directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate secret key: %w", err)
	}
	defer clear(key)
	document := struct {
		ActiveVersion int               `json:"active_version"`
		Keys          map[string]string `json:"keys"`
	}{
		ActiveVersion: 1,
		Keys:          map[string]string{"1": base64.StdEncoding.EncodeToString(key)},
	}
	file, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("secret key file already exists; refusing to replace it")
		}
		return fmt.Errorf("create secret key file: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(clean)
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("write secret key file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync secret key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close secret key file: %w", err)
	}
	cleanup = false
	fmt.Fprintf(stdout, "Initialized Nakpanel service-secret key at %s.\n", clean)
	return nil
}
