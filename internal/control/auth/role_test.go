package auth

import "testing"

func TestRoleValidation(t *testing.T) {
	for _, role := range []Role{RoleAdmin, RoleReseller, RoleClient} {
		if !role.Valid() {
			t.Fatalf("role %q should be valid", role)
		}
	}

	if Role("root").Valid() {
		t.Fatal("role root should be invalid")
	}
}
