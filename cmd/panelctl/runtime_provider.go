package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/control/operator"
	"io"
	"os"
	"syscall"
)

func runRuntimeProviderInUse(ctx context.Context, service *operator.Service, args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("runtime-provider-in-use", flag.ContinueOnError)
	set.SetOutput(stderr)
	provider := set.String("provider", "", "registered provider")
	version := set.String("php-version", "", "PHP major.minor")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected runtime-provider-in-use arguments")
	}
	internalVersion, err := installedInternalPHPVersion("/etc/nakpanel/platform.json")
	if err != nil {
		return err
	}
	used, err := service.RuntimeProviderInUse(ctx, *provider, *version, internalVersion)
	if err != nil {
		return err
	}
	if used {
		fmt.Fprintln(stdout, "in-use")
	} else {
		fmt.Fprintln(stdout, "unused")
	}
	return nil
}

func installedInternalPHPVersion(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return "8.3", nil
	} // Existing Noble installs predate profiles.
	if err != nil {
		return "", fmt.Errorf("open installed platform: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return "", errors.New("installed platform must be a root-owned regular file without group/world write access")
	}
	if info.Size() > 65536 {
		return "", errors.New("installed platform exceeds size bound")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return "", err
	}
	return internalPHPFromProfile(data)
}

func internalPHPFromProfile(data []byte) (string, error) {
	var p struct {
		OS       string `json:"os_id"`
		Version  string `json:"version_id"`
		Profile  string `json:"profile"`
		Internal string `json:"internal_php_version"`
		Pending  bool   `json:"bootstrap_pending"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return "", fmt.Errorf("decode installed platform: %w", err)
	}
	if p.Pending {
		return "", errors.New("installed platform bootstrap pending")
	}
	if p.OS == "ubuntu" && p.Version == "24.04" && p.Profile == "ubuntu-24.04" && p.Internal == "8.3" {
		return p.Internal, nil
	}
	if p.OS == "ubuntu" && p.Version == "26.04" && (p.Profile == "ubuntu-26.04-native" || p.Profile == "ubuntu-26.04-sury") && p.Internal == "8.5" {
		return p.Internal, nil
	}
	return "", errors.New("unknown installed platform/internal PHP mapping")
}
