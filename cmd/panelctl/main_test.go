package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestExtractGlobalActorAndCommandYes(t *testing.T) {
	t.Parallel()
	actor, args, err := extractValueFlag([]string{"--actor", "recovery-shell", "user", "suspend", "client@test", "--yes"}, "--actor", "default")
	if err != nil || actor != "recovery-shell" {
		t.Fatalf("actor=%q args=%#v err=%v", actor, args, err)
	}
	yes, rest := extractBoolFlag(args, "--yes")
	if !yes || strings.Join(rest, " ") != "user suspend client@test" {
		t.Fatalf("yes=%t rest=%#v", yes, rest)
	}
}

func TestNonInteractiveConfirmationRequiresYes(t *testing.T) {
	t.Parallel()
	if err := confirm(bytes.NewBufferString("yes\n"), &bytes.Buffer{}, false, "Proceed?"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error = %v", err)
	}
	if err := confirm(bytes.NewBuffer(nil), &bytes.Buffer{}, true, "Proceed?"); err != nil {
		t.Fatalf("--yes confirmation: %v", err)
	}
}
