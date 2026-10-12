package quota

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"regexp"
	"strings"
	"testing"
)

func TestGitWorkspaceOperationValidation(t *testing.T) {
	for _, action := range []string{"prepare", "fetch", "disconnect"} {
		if err := validateGitOperation(types.GitWorkspaceOperationInput{Action: action}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	for _, action := range []string{"preview", "deploy", "rollback"} {
		if err := validateGitOperation(types.GitWorkspaceOperationInput{Action: action, Revision: "main", ConfirmOverwrite: true}); err == nil {
			t.Fatalf("%s accepted mutable branch", action)
		}
		if err := validateGitOperation(types.GitWorkspaceOperationInput{Action: action, Revision: strings.Repeat("a", 40), ConfirmOverwrite: true}); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{"deploy", "rollback"} {
		if err := validateGitOperation(types.GitWorkspaceOperationInput{Action: action, Revision: strings.Repeat("a", 40)}); err == nil {
			t.Fatalf("%s accepted unconfirmed overwrite", action)
		}
	}
	if err := validateGitOperation(types.GitWorkspaceOperationInput{Action: "push"}); err == nil {
		t.Fatal("accepted unknown action")
	}
}

func TestPersistGitWorkspaceResultStateBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, action, status, deployed, previous string
		disconnected, published                  bool
	}{
		{name: "disconnect revokes connection but retains published revision", action: "disconnect", status: "disconnected", disconnected: true},
		{name: "first deploy clears obsolete rollback revision", action: "deploy", status: "deployed", deployed: strings.Repeat("a", 40), published: true},
		{name: "preview preserves published history", action: "preview", status: "previewed", deployed: strings.Repeat("a", 40)},
		{name: "automatic deploy updates history", action: "fetch", status: "deployed", deployed: strings.Repeat("b", 40), previous: strings.Repeat("a", 40), published: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectExec(regexp.QuoteMeta(persistGitWorkspaceResultSQL)).WithArgs(int64(7), test.deployed, "", int64(4), "", "", test.deployed, test.previous, "null", "null", "null", test.disconnected, test.published).WillReturnResult(sqlmock.NewResult(0, 1))
			err = persistGitWorkspaceResult(context.Background(), db, types.EnsureGitRepositoryReq{RepositoryID: 7, OperationRevision: 4, Action: test.action}, types.EnsureGitRepositoryResult{Status: test.status, DeployedRevision: test.deployed, PreviousRevision: test.previous})
			if err != nil {
				t.Fatal(err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyGitMutationEndpointsFailClosed(t *testing.T) {
	store := &SQLStore{}
	if _, err := store.QueueGitDeployment(context.Background(), 1, 1); err == nil {
		t.Fatal("legacy deploy accepted no immutable revision")
	}
	if err := store.TriggerGitWebhook(context.Background(), 1, strings.Repeat("a", 64)); err == nil {
		t.Fatal("legacy webhook accepted no delivery or branch")
	}
	if err := store.TriggerGitWorkspaceWebhook(context.Background(), 1, strings.Repeat("a", 64), "", "refs/heads/main"); err == nil {
		t.Fatal("webhook accepted missing delivery")
	}
}

func TestGitConnectionTestCannotBecomeAutomaticDeployment(t *testing.T) {
	input := types.EnsureGitRepositoryReq{Action: "test", Automatic: true, Deploy: true}
	if err := validateGitOperation(types.GitWorkspaceOperationInput{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	request := gitAgentWorkspaceRequest(input)
	if request.Action != "fetch" || request.Automatic || request.Deploy {
		t.Fatalf("connection test must only fetch: %+v", request)
	}
	if input.Action != "test" {
		t.Fatal("mutated operation identity")
	}
}
