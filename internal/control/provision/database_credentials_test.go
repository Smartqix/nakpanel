package provision

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

func TestCreateDatabasePreservesExplicitPassword(t *testing.T) {
	repo := &fakeDatabaseRepository{}
	manager := NewManager(nil, WithDatabaseRepository(repo), WithPasswordGenerator(func() (string, error) {
		t.Fatal("explicit password must not invoke generator")
		return "", nil
	}))
	_, err := manager.CreateDatabase(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, types.CreateDatabaseReq{Engine: types.EngineMariaDB, DBName: "np_demo", DBUser: "np_demo_user", Password: "explicit_password_2026"})
	if err != nil {
		t.Fatal(err)
	}
	if repo.req.Password != "explicit_password_2026" {
		t.Fatal("explicit credential was replaced")
	}
}
