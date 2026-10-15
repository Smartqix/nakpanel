package main

import "testing"

func TestVerificationFolderScope(t *testing.T) {
	if !includeFolder("Archive/Projet été", "Archive/Projet été") || includeFolder("Archive/Other", "Archive/Projet été") || !includeFolder("INBOX", "") {
		t.Fatal("verification escaped the selected folder scope")
	}
}
