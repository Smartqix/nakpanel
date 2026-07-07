package web

import (
	"testing"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

func TestFormatQuotaPHPHandlesUnlimitedFields(t *testing.T) {
	tests := []struct {
		name    string
		summary controlquota.Summary
		want    string
	}{
		{
			name:    "no active subscription",
			summary: controlquota.Summary{},
			want:    "no active subscription",
		},
		{
			name: "both defaults",
			summary: controlquota.Summary{
				HasQuota: true,
				Limits:   controlquota.Limits{PHPFPMMaxChildren: -1, PHPMemoryMB: -1},
			},
			want: "agent defaults",
		},
		{
			name: "default children with finite memory",
			summary: controlquota.Summary{
				HasQuota: true,
				Limits:   controlquota.Limits{PHPFPMMaxChildren: -1, PHPMemoryMB: 128},
			},
			want: "agent default / 128 MB",
		},
		{
			name: "finite children with default memory",
			summary: controlquota.Summary{
				HasQuota: true,
				Limits:   controlquota.Limits{PHPFPMMaxChildren: 3, PHPMemoryMB: -1},
			},
			want: "3 children / agent default",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatQuotaPHP(test.summary); got != test.want {
				t.Fatalf("formatQuotaPHP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFormatPlanLimitMB(t *testing.T) {
	if got := formatPlanLimitMB(-1); got != "unlimited" {
		t.Fatalf("formatPlanLimitMB(-1) = %q, want unlimited", got)
	}
	if got := formatPlanLimitMB(512); got != "512 MB" {
		t.Fatalf("formatPlanLimitMB(512) = %q, want 512 MB", got)
	}
}

func TestFormatPlanPHPHandlesUnlimitedFields(t *testing.T) {
	tests := []struct {
		name string
		plan controlquota.Plan
		want string
	}{
		{
			name: "both defaults",
			plan: controlquota.Plan{PHPFPMMaxChildren: -1, PHPMemoryMB: -1},
			want: "agent defaults",
		},
		{
			name: "default children with finite memory",
			plan: controlquota.Plan{PHPFPMMaxChildren: -1, PHPMemoryMB: 256},
			want: "agent default / 256 MB",
		},
		{
			name: "finite limits",
			plan: controlquota.Plan{PHPFPMMaxChildren: 8, PHPMemoryMB: 256},
			want: "8 children / 256 MB",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := formatPlanPHP(test.plan); got != test.want {
				t.Fatalf("formatPlanPHP() = %q, want %q", got, test.want)
			}
		})
	}
}
