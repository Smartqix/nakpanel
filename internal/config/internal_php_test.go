package config

import "testing"

func TestInternalPHPVersionFromEnv(t *testing.T) {
	for _, tc := range []struct {
		value, want string
		invalid     bool
	}{{"", "8.3", false}, {"8.3", "8.3", false}, {"8.5", "8.5", false}, {"8.4", "", true}, {"8.5;id", "", true}} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("NAKPANEL_INTERNAL_PHP_VERSION", tc.value)
			got, err := InternalPHPVersionFromEnv()
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}
