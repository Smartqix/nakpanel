package panelhttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Server) loadMailClientWorkspace(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, data dashboard.Data, view *web.WorkspaceView) bool {
	view.MailView = strings.TrimSpace(r.URL.Query().Get("mail_view"))
	switch view.MailView {
	case "", "addresses", "aliases", "settings", "create-address", "create-alias", "webmail", "enable-domain":
		return true
	case "connection", "edit-address", "edit-alias":
	default:
		http.NotFound(w, r)
		return false
	}
	mailboxID := parseQueryInt64(r, "mailbox_id")
	var site dashboard.Site
	for _, candidate := range data.Sites {
		if candidate.ID == view.DetailID {
			site = candidate
			break
		}
	}
	var domain dashboard.MailDomain
	for _, candidate := range data.SubscriptionServices.MailDomains {
		if candidate.SubscriptionID == site.SubscriptionID && (candidate.SiteID == site.ID || candidate.SiteID == 0 && strings.EqualFold(candidate.Domain, site.Domain)) {
			domain = candidate
			break
		}
	}
	if view.MailView == "edit-address" || view.MailView == "edit-alias" {
		view.MailEditID = parseQueryInt64(r, "resource_id")
		if view.MailEditID > 0 && site.ID > 0 && domain.ID > 0 {
			if view.MailView == "edit-address" {
				for _, mailbox := range data.SubscriptionServices.Mailboxes {
					if mailbox.ID == view.MailEditID && mailbox.MailDomainID == domain.ID && mailbox.SubscriptionID == site.SubscriptionID {
						return true
					}
				}
			} else {
				for _, alias := range data.SubscriptionServices.MailAliases {
					if alias.ID == view.MailEditID && alias.MailDomainID == domain.ID && alias.SubscriptionID == site.SubscriptionID {
						return true
					}
				}
			}
		}
		http.NotFound(w, r)
		return false
	}
	for _, mailbox := range data.SubscriptionServices.Mailboxes {
		if mailbox.ID == mailboxID && mailbox.MailDomainID == domain.ID && mailbox.SubscriptionID == site.SubscriptionID {
			view.MailClientAddress = mailbox.Address
			if !mailbox.Enabled {
				view.MailClientError = "This mailbox is suspended. Enable it before connecting a mail app."
			}
			break
		}
	}
	if site.ID == 0 || domain.ID == 0 || mailboxID <= 0 || view.MailClientAddress == "" {
		http.NotFound(w, r)
		return false
	}
	view.MailClientSiteID = site.ID
	if !domain.Enabled || domain.Status != "in_sync" || site.Status != "active" {
		view.MailClientError = "Mail service is not ready. Ask your provider to check this domain."
	}
	subFound := false
	for _, sub := range data.Subscriptions {
		if sub.ID == site.SubscriptionID {
			subFound = true
			if sub.Status != "active" || sub.MaxMailboxes == 0 {
				view.MailClientError = "Mail is unavailable for this subscription."
			}
			for _, provider := range data.Resellers {
				if provider.ID == sub.ResellerID && provider.Status != "active" {
					view.MailClientError = "The provider account is suspended."
				}
			}
		}
	}
	if !subFound {
		http.NotFound(w, r)
		return false
	}
	for _, account := range data.SubscriptionServices.Accounts {
		if account.SubscriptionID == site.SubscriptionID && (!account.EffectivePolicy.Permissions.Mail || !account.EffectivePolicy.Mail.Enabled || account.EffectivePolicy.Resources.MaxMailboxes == 0) {
			view.MailClientError = "Mail is disabled by the subscription policy."
		}
	}
	for _, customer := range data.Customers {
		if customer.ID == site.CustomerID && customer.Status != "active" {
			view.MailClientError = "The customer account is suspended."
		}
	}
	if view.MailClientError == "" {
		reader, ok := s.mail.(interface {
			MailClientSettings(context.Context, auth.SessionUser, int64) (types.MailClientProfile, error)
		})
		if !ok {
			view.MailClientError = "Mail connection settings are not available. Contact your provider."
		} else {
			profile, err := reader.MailClientSettings(r.Context(), actor, site.SubscriptionID)
			if err != nil {
				view.MailClientError = "Mail connection settings could not be verified. Contact your provider."
			} else {
				view.MailClient = profile
			}
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if r.Header.Get("X-Nakpanel-Mail") == "connection" {
		renderPage(w, r, web.MailClientContent(*view))
		return false
	}
	return true
}
