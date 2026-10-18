package quota

import "testing"

func TestResolveReadyPHPVersion(t *testing.T) {
	limits := Limits{PHPAllowlist: "8.4,8.5,8.3", DefaultPHPVersion: "8.3"}
	for _, tt := range []struct {
		name, requested string
		ready           []string
		want            string
		fail            bool
	}{
		{"noble preference", "", []string{"8.3", "8.4", "8.5"}, "8.4", false},
		{"native only", "", []string{"8.5"}, "8.5", false},
		{"configured default", "", []string{"8.3", "8.5"}, "8.3", false},
		{"empty", "", nil, "", true},
		{"explicit unavailable", "8.3", []string{"8.5"}, "", true},
		{"explicit preserved", "8.3", []string{"8.3", "8.4", "8.5"}, "8.3", false},
		{"disallowed", "8.2", []string{"8.2", "8.5"}, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveReadyPHPVersion(limits, tt.requested, tt.ready)
			if (err != nil) != tt.fail || got != tt.want {
				t.Fatalf("got %q, %v; want %q fail=%v", got, err, tt.want, tt.fail)
			}
		})
	}
}
