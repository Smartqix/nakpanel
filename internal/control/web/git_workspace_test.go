package web

import (
	"bytes"
	"context"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
	"strings"
	"testing"
)

func TestGitSettingsPreserveScopeAndHideNewHostedMode(t *testing.T) {
	var out bytes.Buffer
	err := gitSettingsForm(dashboard.Site{ID: 58}, types.SubscriptionSummary{ID: 39}, types.GitRepository{Mode: "remote", Branch: "main", DeployTarget: "."}, WorkspaceView{CSRFToken: "csrf-test", SupportCustomerID: 12}).Render(context.Background(), &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`action="/sites/58/git"`, `name="subscription_id" value="39"`, `value="csrf-test"`, `name="deployment_mode"`, `value="disabled"`, `name="trust_host"`, `data-git-prepare`, `data-git-prepared-key`, `name="connect" value="yes"`, `Add Repository`, `public_html`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out.String(), `value="hosted"`) {
		t.Fatal("new hosted mode exposed")
	}
}

func TestGitCreationUsesSharedDialogFooter(t *testing.T) {
	var out bytes.Buffer
	if err := gitSettingsForm(dashboard.Site{ID: 58}, types.SubscriptionSummary{ID: 39}, types.GitRepository{Mode: "remote", Branch: "main", DeployTarget: "."}, WorkspaceView{}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if !strings.Contains(html, `np-dialog-actions`) {
		t.Fatal("Git creation must use the shared dialog action footer")
	}
	if strings.Index(html, `>Cancel</button>`) > strings.LastIndex(html, `Add Repository`) {
		t.Fatal("Cancel must precede the primary action")
	}
	if !strings.Contains(html, `icons.svg#chevron-right`) {
		t.Fatal("Git disclosures must use a bundled icon")
	}
}

func TestGitRemovedRepositoryReturnsEmptyWithRevisionPreserved(t *testing.T) {
	repository := types.GitRepository{ID: 7, SiteID: 58, OperationRevision: 9, ConnectionStatus: "disconnected", ConvergenceStatus: "in_sync"}
	if gitConnectionVisible(repository) {
		t.Fatal("removed repository still visible")
	}
	draft := gitNewRepository([]types.GitRepository{repository}, 58)
	if draft.OperationRevision != 9 || draft.ID != 7 || draft.RemoteURL != "" {
		t.Fatalf("bad reconnect form: %+v", draft)
	}
	repository.ConvergenceStatus = "pending"
	if !gitConnectionVisible(repository) {
		t.Fatal("pending removal hidden prematurely")
	}
}

func TestGitConnectedSeparatesFetchedAndPublishedRevision(t *testing.T) {
	var out bytes.Buffer
	err := gitConnected(dashboard.Site{ID: 58}, types.SubscriptionSummary{ID: 39}, types.GitRepository{ID: 7, Mode: "remote", FetchedRevision: "fetch-sha", DeployedRevision: "published-sha", DeployTarget: "web"}, dashboard.Data{}, WorkspaceView{}).Render(context.Background(), &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`data-git-fetched>fetch-sha`, `data-git-deployed>published-sha`, `public_html/web`, `/git/preview`, `/git/rollback`, `/git/disconnect`, `Published files stay in place`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestGitActionPlainFormContainsConcurrencyAndConfirmation(t *testing.T) {
	var out bytes.Buffer
	repository := types.GitRepository{OperationRevision: 9, FetchedRevision: strings.Repeat("a", 40), ConnectionStatus: "connected", DeploymentMode: "manual"}
	err := gitAction(dashboard.Site{ID: 58}, types.SubscriptionSummary{ID: 39}, repository, WorkspaceView{}, "deploy", "Deploy", gitActionDisabled(repository, "deploy")).Render(context.Background(), &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`name="expected_revision" value="9"`, `name="revision" value="` + repository.FetchedRevision + `"`, `<noscript>`, `name="confirm" value="yes" required`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out.String(), `disabled`) {
		t.Fatal("valid plain form deployment remains disabled")
	}
}

func TestGitSSHKeyOnboardingMetadata(t *testing.T) {
	var out bytes.Buffer
	repo := types.GitRepository{ID: 1, Mode: "remote", RemoteURL: "git@github.com:team/website.git", DeployPublicKey: "ssh-ed25519 YWJj comment"}
	if err := gitConnected(dashboard.Site{ID: 58, Domain: "kofik.com"}, types.SubscriptionSummary{ID: 39}, repo, dashboard.Data{}, WorkspaceView{}).Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Nakpanel - kofik.com - website - site-58", "Copy title", "Deploy-key fingerprint", "SHA256:", "Copy public key"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
