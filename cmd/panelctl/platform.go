package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"syscall"

	"github.com/nakroteck/nakpanel/internal/control/agentclient"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

type platformRecord struct {
	OSID               string   `json:"os_id"`
	VersionID          string   `json:"version_id"`
	Codename           string   `json:"codename"`
	Architecture       string   `json:"architecture"`
	Profile            string   `json:"profile"`
	InternalPHPVersion string   `json:"internal_php_version"`
	HostingPHPVersions []string `json:"hosting_php_versions"`
	BootstrapPending   bool     `json:"bootstrap_pending"`
}

func (p platformRecord) validateBootstrap(profile string) error {
	if profile != "ubuntu-26.04-native" || p.Profile != profile || !p.BootstrapPending || p.OSID != "ubuntu" || p.VersionID != "26.04" || p.Codename != "resolute" || (p.Architecture != "amd64" && p.Architecture != "arm64") || p.InternalPHPVersion != "8.5" || !reflect.DeepEqual(p.HostingPHPVersions, []string{"8.5"}) {
		return errors.New("plan bootstrap requires the recorded, pending fresh ubuntu-26.04-native profile")
	}
	return nil
}

func readBootstrapPlatformRecord(path string) (platformRecord, error) {
	var record platformRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() {
		return record, errors.New("platform record must be a regular root-owned file")
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return record, err
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !os.SameFile(info, opened) || !ok || stat.Uid != 0 || opened.Mode().Perm()&0022 != 0 {
		return record, errors.New("platform record must be root-owned and not writable by other users")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	if err = decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("read platform record: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return record, errors.New("platform record contains trailing data")
	}
	return record, nil
}

func runPlatform(ctx context.Context, databaseURL, agentSocket, actor string, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "bootstrap-plans" {
		return errors.New("usage: panelctl platform bootstrap-plans --profile ubuntu-26.04-native [--discard-demo-subscriptions]")
	}
	flags := flag.NewFlagSet("platform bootstrap-plans", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profile := flags.String("profile", "", "recorded fresh installation profile")
	discardDemo := flags.Bool("discard-demo-subscriptions", false, "discard only the exact untouched migration-created demo subscriptions")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected platform bootstrap arguments")
	}
	record, err := readBootstrapPlatformRecord("/etc/nakpanel/platform.json")
	if err != nil {
		return err
	}
	if err = record.validateBootstrap(*profile); err != nil {
		return err
	}
	capabilities, err := agentclient.New(agentSocket).RuntimeCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("load ready PHP inventory: %w", err)
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = controlquota.BootstrapNativePlans(ctx, db, *profile, controlquota.ReadyPHPVersions(capabilities), actor, *discardDemo); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "native plan bootstrap committed; installer may clear bootstrap_pending")
	return nil
}
