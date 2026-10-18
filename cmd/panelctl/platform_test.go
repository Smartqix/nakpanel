package main

import "testing"

func TestPlatformBootstrapRequiresRecordedPendingNativeProfile(t *testing.T) {
	valid := platformRecord{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Architecture: "amd64", Profile: "ubuntu-26.04-native", InternalPHPVersion: "8.5", HostingPHPVersions: []string{"8.5"}, BootstrapPending: true}
	if err := valid.validateBootstrap("ubuntu-26.04-native"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		change func(*platformRecord)
	}{
		{"completed", func(p *platformRecord) { p.BootstrapPending = false }},
		{"update noble", func(p *platformRecord) { p.Profile = "ubuntu-24.04"; p.VersionID = "24.04" }},
		{"wrong OS", func(p *platformRecord) { p.OSID = "debian" }},
		{"wrong codename", func(p *platformRecord) { p.Codename = "noble" }},
		{"wrong internal runtime", func(p *platformRecord) { p.InternalPHPVersion = "8.3" }},
		{"wrong hosting runtime", func(p *platformRecord) { p.HostingPHPVersions = []string{"8.4", "8.5"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			record := valid
			tt.change(&record)
			if err := record.validateBootstrap("ubuntu-26.04-native"); err == nil {
				t.Fatal("unsafe platform record accepted")
			}
		})
	}
	if err := valid.validateBootstrap("ubuntu-24.04"); err == nil {
		t.Fatal("caller profile mismatch accepted")
	}
}
