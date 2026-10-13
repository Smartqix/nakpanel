package panelhttp

import (
	"net/http"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

func applyCertificateQueuedNotice(r *http.Request, route string, siteID int64, data *dashboard.Data) {
	if route == "site-detail" && r.URL.Query().Get("notice") == "website-secured" && data.NoticeKind != dashboard.NoticeError {
		data.Notice, data.NoticeKind = "", ""
		for _, site := range data.Sites {
			if site.ID == siteID {
				if site.TLSStatus == "active" && site.HTTPSRedirect && site.SettingsStatus == "in_sync" {
					data.Notice, data.NoticeKind = "Website created and secured.", dashboard.NoticeSuccess
				} else {
					data.Notice, data.NoticeKind = "Website created. Review its SSL/TLS and HTTPS setup.", dashboard.NoticeWarning
				}
				break
			}
		}
		return
	}
	if route != "site-detail" || r.URL.Query().Get("notice") != "certificate-queued" || data.NoticeKind == dashboard.NoticeError {
		return
	}
	for _, site := range data.Sites {
		if site.ID != siteID {
			continue
		}
		switch site.TLSStatus {
		case "pending":
			data.Notice, data.NoticeKind = "Certificate request in progress. Waiting for the issuer to respond.", dashboard.NoticeInfo
		case "failed":
			data.Notice, data.NoticeKind = "Certificate request failed.", dashboard.NoticeError
			if message := sanitizeNoticeText(strings.TrimSpace(site.TLSLastError)); message != "" {
				data.Notice += " " + message
			}
		case "active":
			data.Notice, data.NoticeKind = "Certificate installed successfully.", dashboard.NoticeSuccess
		default:
			data.Notice, data.NoticeKind = "", ""
		}
		return
	}
}
