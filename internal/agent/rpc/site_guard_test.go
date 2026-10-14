package rpc

import (
	"context"
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/agent/ops"
	"github.com/nakroteck/nakpanel/internal/types"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSiteGuardUnknownOperationPreservesValidationContract(t *testing.T) {
	_, err := prepareSiteGuard(types.Request{Op: "totally_unknown_op"}, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("unknown operation must fail closed with the existing validation contract: %v", err)
	}
}

func TestSiteGuardRejectsRemovedMutation(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	registry := ops.NewSiteIdentityRegistry(filepath.Join(parent, "identities"))
	id := types.SiteIdentity{SiteID: 1, SubscriptionID: 2, Username: "nps2", Domain: "addon.test"}
	registry.WithCreation(context.Background(), []types.SiteIdentity{id}, func(context.Context) error { return nil })
	registry.MarkRemoved(context.Background(), 5, 1, []types.SiteIdentity{id})
	data, _ := json.Marshal(types.CreateSiteReq{SiteID: 1, SubscriptionID: 2, Username: "nps2", Domain: "addon.test", PHPVersion: "8.4"})
	if _, err := prepareSiteGuard(types.Request{Op: types.OpCreateSite, Data: data}, registry); err != nil {
		t.Fatal(err)
	}
	dispatcher := NewDispatcher(nil, Options{SiteGuard: registry})
	response := dispatcher.Dispatch(context.Background(), types.Request{ID: "stale", Op: types.OpCreateSite, Data: data})
	if response.OK {
		t.Fatal("removed mutation passed agent guard")
	}
}

func TestSiteIdentitySharedSnapshotExcludesTombstones(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	registry := ops.NewSiteIdentityRegistry(filepath.Join(parent, "identities"))
	id := types.SiteIdentity{SiteID: 1, SubscriptionID: 2, Username: "nps2", Domain: "addon.test"}
	sibling := id
	sibling.SiteID = 2
	sibling.Domain = "sibling.test"
	registry.WithCreation(context.Background(), []types.SiteIdentity{id, sibling}, func(context.Context) error { return nil })
	registry.MarkRemoved(context.Background(), 5, 1, []types.SiteIdentity{id})
	request := types.EnsureSubscriptionAccountReq{SubscriptionID: 2, Username: "nps2", Domains: []types.SubscriptionDomain{{SiteID: 1, Domain: id.Domain}, {SiteID: 2, Domain: sibling.Domain}}, Tasks: []types.ScheduledTask{{ID: 1, SiteID: 1, Domain: id.Domain}, {ID: 2, SiteID: 2, Domain: sibling.Domain}}}
	data, _ := json.Marshal(request)
	prepared, err := prepareSiteGuard(types.Request{Op: types.OpEnsureSubscriptionAccount, Data: data}, registry)
	if err != nil {
		t.Fatal(err)
	}
	var actual types.EnsureSubscriptionAccountReq
	if err = json.Unmarshal(prepared.request.Data, &actual); err != nil {
		t.Fatal(err)
	}
	if len(actual.Domains) != 1 || actual.Domains[0].SiteID != 2 || len(actual.Tasks) != 1 || actual.Tasks[0].SiteID != 2 {
		t.Fatalf("stale snapshot survived: %#v", actual)
	}
}

func TestSiteGuardClassifiesAllRegisteredOperations(t *testing.T) {
	set := token.NewFileSet()
	dispatcher, err := parser.ParseFile(set, "dispatcher.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := parser.ParseFile(set, "site_guard.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	collect := func(file *ast.File) map[string]bool {
		out := map[string]bool{}
		ast.Inspect(file, func(node ast.Node) bool {
			if clause, ok := node.(*ast.CaseClause); ok {
				for _, value := range clause.List {
					if selector, ok := value.(*ast.SelectorExpr); ok {
						if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "types" {
							out[selector.Sel.Name] = true
						}
					}
				}
			}
			return true
		})
		return out
	}
	classifications := collect(guard)
	for name := range collect(dispatcher) {
		if !classifications[name] {
			t.Errorf("registered RPC %s has no removal classification", name)
		}
	}
}
