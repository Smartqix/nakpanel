package backup

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

func TestParkExistingIdentityFreesArchivedNumericIDs(t *testing.T) {
	groups := map[string]int{"nps1": 986, "nps2": 987, "system-service": 120}
	users := map[string]int{"nps1": 995, "nps2": 997, "system-service": 120}

	originalRun := restoreIdentityRunQuiet
	originalGroupGID := restoreIdentityLookupGroupGID
	originalUserUID := restoreIdentityLookupUserUID
	originalGroupName := restoreIdentityLookupGroupName
	originalUserName := restoreIdentityLookupUserName
	t.Cleanup(func() {
		restoreIdentityRunQuiet = originalRun
		restoreIdentityLookupGroupGID = originalGroupGID
		restoreIdentityLookupUserUID = originalUserUID
		restoreIdentityLookupGroupName = originalGroupName
		restoreIdentityLookupUserName = originalUserName
	})

	restoreIdentityLookupGroupGID = func(name string) (int, error) {
		id, ok := groups[name]
		if !ok {
			return 0, errors.New("not found")
		}
		return id, nil
	}
	restoreIdentityLookupUserUID = func(name string) (int, error) {
		id, ok := users[name]
		if !ok {
			return 0, errors.New("not found")
		}
		return id, nil
	}
	restoreIdentityLookupGroupName = func(id int) (string, error) {
		for name, candidate := range groups {
			if candidate == id {
				return name, nil
			}
		}
		return "", errors.New("not found")
	}
	restoreIdentityLookupUserName = func(id int) (string, error) {
		for name, candidate := range users {
			if candidate == id {
				return name, nil
			}
		}
		return "", errors.New("not found")
	}
	restoreIdentityRunQuiet = func(_ context.Context, command string, args ...string) error {
		if len(args) != 3 || args[0] != "--gid" && args[0] != "--uid" {
			return errors.New("unexpected identity command")
		}
		id, err := strconv.Atoi(args[1])
		if err != nil {
			return err
		}
		switch command {
		case "groupmod":
			groups[args[2]] = id
		case "usermod":
			users[args[2]] = id
		default:
			return errors.New("unexpected identity command")
		}
		return nil
	}

	identity := SystemIdentity{
		Groups: []SystemGroup{{Name: "nps1", GID: 985}, {Name: "nps2", GID: 986}},
		Users:  []SystemUser{{Name: "nps1", UID: 994}, {Name: "nps2", UID: 995}},
	}
	if err := parkExistingIdentity(context.Background(), identity, nil); err != nil {
		t.Fatalf("parkExistingIdentity returned error: %v", err)
	}

	for _, target := range []int{985, 986} {
		if name, err := restoreIdentityLookupGroupName(target); err == nil {
			t.Fatalf("archived gid %d is still occupied by %s", target, name)
		}
	}
	for _, target := range []int{994, 995} {
		if name, err := restoreIdentityLookupUserName(target); err == nil {
			t.Fatalf("archived uid %d is still occupied by %s", target, name)
		}
	}
	if groups["system-service"] != 120 || users["system-service"] != 120 {
		t.Fatal("parking archived identities changed an unrelated system account")
	}
}
