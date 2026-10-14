package provision

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/types"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTargetSiteJobScopeKeepsSiblingsPostgreSQL(t *testing.T) {
	db, service, actor, req := removalServiceFixture(t)
	preview, err := service.PreviewSiteRemoval(context.Background(), actor, req.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ kind, args string }{{"issue_cert", `{"site_id":2}`}, {"issue_cert", `{"site_id":1}`}, {"configure_mail", `{"revision":2}`}, {"configure_webmail", `{"domain":"addon.test"}`}, {"reconcile_system", `{"sites":[{"site_id":2},{"site_id":1}]}`}, {"reconcile_system", `{"sites":null}`}} {
		if _, err := db.Exec("INSERT INTO river_job(kind,args,queue,max_attempts) VALUES($1,$2,'heavy',3)", item.kind, item.args); err != nil {
			t.Fatal(err)
		}
	}
	predicate, args := TargetSiteJobScope(preview.Snapshot)
	var count int
	if err := db.QueryRow("SELECT count(*) FROM river_job WHERE "+predicate, args...).Scan(&count); err != nil || count != 2 {
		t.Fatalf("target jobs=%d %v", count, err)
	}
	if strings.Contains(predicate, "addon.test") {
		t.Fatal("domain interpolated into SQL")
	}
}
func TestTargetSiteJobScopeClassifiesEveryKind(t *testing.T) {
	paths, err := filepath.Glob("../*/*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != "Kind" {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if result, ok := node.(*ast.ReturnStmt); ok {
					for _, value := range result.Results {
						if literal, ok := value.(*ast.BasicLit); ok && literal.Kind == token.STRING {
							kind, _ := strconv.Unquote(literal.Value)
							if _, ok := removalJobClassification[kind]; !ok {
								t.Errorf("job kind %s lacks removal classification", kind)
							}
						}
					}
				}
				return true
			})
		}
	}
}
func TestTargetSiteJobScopeIncludesDestinationStaging(t *testing.T) {
	snapshot := types.SiteRemovalSnapshot{Sites: []types.SiteRemovalSite{{SiteID: 3, Domain: "target.test"}}, Resources: []types.SiteRemovalResource{{Kind: "staging", ID: 12, SiteID: 99, ParentID: 3}}}
	predicate, args := TargetSiteJobScope(snapshot)
	if !strings.Contains(predicate, "run_staging_operation") || len(args) == 0 {
		t.Fatal("destination-only staging omitted")
	}
}
