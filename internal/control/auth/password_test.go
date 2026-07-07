package auth

import "testing"

func TestHashPasswordVerifiesAndRejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple", TestPasswordParams)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword returned false for the correct password")
	}

	ok, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword returned error for wrong password: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword returned true for the wrong password")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	ok, err := VerifyPassword("password", "not-a-phc-hash")
	if err == nil {
		t.Fatal("VerifyPassword returned nil error for malformed hash")
	}
	if ok {
		t.Fatal("VerifyPassword returned true for malformed hash")
	}
}
