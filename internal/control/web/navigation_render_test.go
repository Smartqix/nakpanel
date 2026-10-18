package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestRoutedMainMatchesFullDocument(t *testing.T) {
	for _, route := range []string{"dashboard", "sites", "subscriptions"} {
		view := WorkspaceView{Route: route}
		data := dashboard.Data{Notice: "Saved"}
		user := auth.SessionUser{Role: auth.RoleAdmin}
		render := func(c templ.Component) string {
			var b bytes.Buffer
			if err := c.Render(context.Background(), &b); err != nil {
				t.Fatal(err)
			}
			return b.String()
		}
		full := render(RoutedDashboardPage("Panel", user, data, DashboardActions{}, view))
		if !strings.Contains(full, `<div class="np-nav-progress" aria-hidden="true"></div>`) {
			t.Fatal("missing navigation progress bar")
		}
		start := strings.Index(full, `<main class="np-routed-content" id="main-content">`)
		if start < 0 {
			t.Fatal("missing main")
		}
		start += len(`<main class="np-routed-content" id="main-content">`)
		end := strings.Index(full[start:], "</main>")
		if got, want := render(routedMain(user, data, DashboardActions{}, view)), full[start:start+end]; got != want {
			t.Fatalf("%s main differs\ngot %s\nwant %s", route, got, want)
		}
	}
}

func TestFragmentDocumentRequirements(t *testing.T) {
	for _, tc := range []struct {
		view WorkspaceView
		full bool
	}{
		{WorkspaceView{Route: "site-new"}, true},
		{WorkspaceView{FileEditor: &FileEditorView{}}, true},
		{WorkspaceView{Route: "site-setup", SiteSetup: &types.SiteSetupStatus{State: "pending"}}, false},
		{WorkspaceView{Route: "site-setup", SiteSetup: &types.SiteSetupStatus{State: "pending"}, SiteSetupTimedOut: true}, false},
		{WorkspaceView{Route: "site-setup", SiteSetup: &types.SiteSetupStatus{State: "ready"}}, false},
	} {
		var b bytes.Buffer
		if err := RoutedFragment("Panel", auth.SessionUser{}, dashboard.Data{}, DashboardActions{}, tc.view).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(b.String(), `data-full-document="true"`); got != tc.full {
			t.Fatalf("%+v fragment: %s", tc.view, b.String())
		}
		if got := strings.Contains(b.String(), `data-np-fragment`); got == tc.full {
			t.Fatalf("unexpected main: %s", b.String())
		}
	}
}

func TestSubscriptionNavigationScope(t *testing.T) {
	var b bytes.Buffer
	data := dashboard.Data{Subscriptions: []types.SubscriptionSummary{{ID: 20}}}
	if err := RoutedDashboardPage("Panel", auth.SessionUser{}, data, DashboardActions{}, WorkspaceView{Route: "subscription-detail", DetailID: 20}).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `<div class="np-detail-split" data-np-nav-scope-body>`) {
		t.Fatal("subscription body has no navigation scope")
	}
}

func TestDocumentOnlyFormsMarker(t *testing.T) {
	for _, tc := range []struct {
		view WorkspaceView
		want bool
	}{
		{WorkspaceView{Route: "site-new"}, true},
		{WorkspaceView{Route: "site-file-edit", FileEditor: &FileEditorView{}}, true},
		{WorkspaceView{Route: "sites"}, false},
	} {
		var b bytes.Buffer
		if err := RoutedDashboardPage("Panel", auth.SessionUser{}, dashboard.Data{}, DashboardActions{}, tc.view).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		body := b.String()
		start := strings.Index(body, "<body")
		end := start + strings.Index(body[start:], ">")
		if got := strings.Contains(body[start:end], "data-np-document-only"); got != tc.want {
			t.Errorf("%s document-only = %v, want %v", tc.view.Route, got, tc.want)
		}
	}
}

func TestFragmentSiteDialogShell(t *testing.T) {
	for _, tc := range []struct {
		route                 string
		canCreate, wantDialog bool
	}{
		{"sites", true, true},
		{"subscriptions", true, true},
		{"sites", false, false},
		{"site-new", true, false},
	} {
		var b bytes.Buffer
		data := dashboard.Data{Subscriptions: []types.SubscriptionSummary{{ID: 99, SubscriptionName: "New hosting"}}}
		if err := RoutedFragment("Panel", auth.SessionUser{Role: auth.RoleAdmin}, data, DashboardActions{CanCreateSite: tc.canCreate}, WorkspaceView{Route: tc.route}).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		body := b.String()
		start := strings.Index(body, `<template data-np-shell="site-dialog">`)
		if start < 0 {
			t.Fatalf("%s canCreate=%v: missing site-dialog template", tc.route, tc.canCreate)
		}
		dialog := body[start : start+strings.Index(body[start:], "</template>")]
		if got := strings.Contains(dialog, `id="site-dialog"`); got != tc.wantDialog {
			t.Errorf("dialog=%v want %v", got, tc.wantDialog)
		}
		if tc.wantDialog && !strings.Contains(dialog, `value="99"`) {
			t.Error("dialog did not receive the current subscriptions")
		}
	}
}

func TestFragmentCustomerDialogShell(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       auth.Role
		canManage  bool
		route      string
		wantDialog bool
	}{
		{"admin", auth.RoleAdmin, true, "customers", true},
		{"reseller", auth.RoleReseller, true, "customers", true},
		{"admin_without_quota_management", auth.RoleAdmin, false, "customers", false},
		{"reseller_without_quota_management", auth.RoleReseller, false, "customers", false},
		{"client_with_quota_management", auth.RoleClient, true, "dashboard", false},
		{"client_without_quota_management", auth.RoleClient, false, "dashboard", false},
		{"document_only_route", auth.RoleAdmin, true, "site-new", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			view := WorkspaceView{Route: tc.route, CSRFToken: "current-customer-token", SupportCustomerID: 42}
			if err := RoutedFragment("Panel", auth.SessionUser{Role: tc.role}, dashboard.Data{}, DashboardActions{CanManageQuotas: tc.canManage}, view).Render(context.Background(), &b); err != nil {
				t.Fatal(err)
			}
			body := b.String()
			marker := `<template data-np-shell="customer-dialog">`
			start := strings.Index(body, marker)
			if start < 0 {
				t.Fatal("missing customer-dialog template")
			}
			start += len(marker)
			end := strings.Index(body[start:], "</template>")
			if end < 0 {
				t.Fatal("unterminated customer-dialog template")
			}
			dialog := body[start : start+end]
			if !tc.wantDialog {
				if strings.TrimSpace(dialog) != "" {
					t.Fatal("customer-dialog template must be empty without customer management permission")
				}
				return
			}
			for _, want := range []string{`id="customer-dialog"`, `action="/customers"`, `name="csrf_token" value="current-customer-token"`, `name="support_customer_id" value="42"`} {
				if !strings.Contains(dialog, want) {
					t.Errorf("customer-dialog template missing current form value %s", want)
				}
			}
		})
	}
}
