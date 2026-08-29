package provision

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/platformadmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type mailQueueReader interface {
	QueryMailQueue(context.Context, types.MailQueueQueryReq) (types.MailQueueQueryResult, error)
	InspectQueuedMail(context.Context, types.InspectQueuedMailReq) (types.MailQueueMessage, error)
}

type mailJournalReader interface {
	ReadJournal(context.Context, types.ReadJournalReq) (types.ReadJournalResult, error)
}

func (m *Manager) SearchMailQueue(ctx context.Context, actor auth.SessionUser, input platformadmin.MailQueueFilter) (types.MailQueueQueryResult, error) {
	if actor.Role != auth.RoleAdmin {
		return types.MailQueueQueryResult{}, ErrForbidden
	}
	reader, ok := m.mailAgent.(mailQueueReader)
	if !ok {
		return types.MailQueueQueryResult{}, errors.New("mail queue inspection is not configured")
	}
	filter, err := platformadmin.NormalizeMailQueueFilter(input)
	if err != nil {
		return types.MailQueueQueryResult{}, err
	}
	if filter.State == platformadmin.MailQueueStateHeld {
		return types.MailQueueQueryResult{}, errors.New("held mail is not supported by the installed mail server")
	}
	return reader.QueryMailQueue(ctx, types.MailQueueQueryReq{
		State: string(filter.State), SenderDomain: filter.SenderDomain,
		RecipientDomain: filter.RecipientDomain, OlderThanMins: filter.OlderThanMins, Limit: filter.Limit,
	})
}

func (m *Manager) InspectQueuedMail(ctx context.Context, actor auth.SessionUser, messageID string) (types.MailQueueMessage, error) {
	if actor.Role != auth.RoleAdmin {
		return types.MailQueueMessage{}, ErrForbidden
	}
	reader, ok := m.mailAgent.(mailQueueReader)
	if !ok {
		return types.MailQueueMessage{}, errors.New("mail queue inspection is not configured")
	}
	return reader.InspectQueuedMail(ctx, types.InspectQueuedMailReq{MessageID: strings.TrimSpace(messageID)})
}

// ReadMailLogs hard-codes the allowlisted Stalwart journal source and applies
// a smaller limit than the general server journal endpoint.
func (m *Manager) ReadMailLogs(ctx context.Context, actor auth.SessionUser, since time.Time, afterCursor string, limit int) (types.ReadJournalResult, error) {
	if actor.Role != auth.RoleAdmin {
		return types.ReadJournalResult{}, ErrForbidden
	}
	reader, ok := m.mailAgent.(mailJournalReader)
	if !ok {
		return types.ReadJournalResult{}, errors.New("mail log inspection is not configured")
	}
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 500 {
		return types.ReadJournalResult{}, errors.New("mail log limit must be between 1 and 500")
	}
	now := time.Now().UTC()
	if since.IsZero() {
		since = now.Add(-time.Hour)
	}
	if since.After(now) || now.Sub(since) > 7*24*time.Hour {
		return types.ReadJournalResult{}, errors.New("mail log range must be within the last seven days")
	}
	return reader.ReadJournal(ctx, types.ReadJournalReq{
		SourceIDs: []string{"mail"}, Since: since, Until: now,
		AfterCursor: strings.TrimSpace(afterCursor), Limit: limit,
	})
}
