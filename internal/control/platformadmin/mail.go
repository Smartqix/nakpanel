package platformadmin

import (
	"errors"
	"fmt"
	"strings"
)

type MailQueueState string

const (
	MailQueueStateAny      MailQueueState = ""
	MailQueueStateQueued   MailQueueState = "queued"
	MailQueueStateDeferred MailQueueState = "deferred"
	MailQueueStateHeld     MailQueueState = "held"
)

type MailQueueAction string

const (
	MailQueueActionRetry   MailQueueAction = "retry"
	MailQueueActionHold    MailQueueAction = "hold"
	MailQueueActionRelease MailQueueAction = "release"
	MailQueueActionDelete  MailQueueAction = "delete"
)

// MailQueueFilter is intentionally limited to indexed, metadata-only fields.
// It cannot request message bodies or pass an expression to Stalwart.
type MailQueueFilter struct {
	State           MailQueueState `json:"state,omitempty"`
	SenderDomain    string         `json:"sender_domain,omitempty"`
	RecipientDomain string         `json:"recipient_domain,omitempty"`
	OlderThanMins   int            `json:"older_than_minutes,omitempty"`
	Limit           int            `json:"limit,omitempty"`
	Cursor          string         `json:"cursor,omitempty"`
}

// NormalizeMailQueueFilter applies stable defaults and canonicalizes domains
// before validation. Callers should persist or dispatch the returned value.
func NormalizeMailQueueFilter(input MailQueueFilter) (MailQueueFilter, error) {
	input.SenderDomain = strings.ToLower(strings.TrimSpace(input.SenderDomain))
	input.RecipientDomain = strings.ToLower(strings.TrimSpace(input.RecipientDomain))
	input.Cursor = strings.TrimSpace(input.Cursor)
	if input.Limit == 0 {
		input.Limit = 50
	}
	if err := input.Validate(); err != nil {
		return MailQueueFilter{}, err
	}
	return input, nil
}

func (f MailQueueFilter) Validate() error {
	switch f.State {
	case MailQueueStateAny, MailQueueStateQueued, MailQueueStateDeferred, MailQueueStateHeld:
	default:
		return fmt.Errorf("unsupported mail queue state %q", f.State)
	}
	if f.SenderDomain != "" {
		if err := validateDomain("sender_domain", f.SenderDomain); err != nil {
			return err
		}
	}
	if f.RecipientDomain != "" {
		if err := validateDomain("recipient_domain", f.RecipientDomain); err != nil {
			return err
		}
	}
	if f.OlderThanMins < 0 || f.OlderThanMins > 60*24*90 {
		return errors.New("older_than_minutes must be between 0 and 129600")
	}
	if f.Limit < 1 || f.Limit > 200 {
		return errors.New("mail queue limit must be between 1 and 200")
	}
	if f.Cursor != "" && !cursorRE.MatchString(f.Cursor) {
		return errors.New("mail queue cursor is invalid")
	}
	return nil
}

// MailQueueActionRequest operates only on queue IDs returned by a prior
// metadata query. Delete requires an explicit consequence acknowledgement.
type MailQueueActionRequest struct {
	Action     MailQueueAction `json:"action"`
	MessageIDs []string        `json:"message_ids"`
	Confirmed  bool            `json:"confirmed,omitempty"`
}

func (r MailQueueActionRequest) Validate() error {
	switch r.Action {
	case MailQueueActionRetry, MailQueueActionHold, MailQueueActionRelease, MailQueueActionDelete:
	default:
		return fmt.Errorf("unsupported mail queue action %q", r.Action)
	}
	if len(r.MessageIDs) < 1 || len(r.MessageIDs) > 100 {
		return errors.New("mail queue action requires between 1 and 100 message IDs")
	}
	seen := make(map[string]struct{}, len(r.MessageIDs))
	for _, id := range r.MessageIDs {
		if !queueIDRE.MatchString(id) {
			return fmt.Errorf("mail queue message ID %q is invalid", id)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("mail queue message ID %q is duplicated", id)
		}
		seen[id] = struct{}{}
	}
	if r.Action == MailQueueActionDelete && !r.Confirmed {
		return errors.New("deleting queued mail requires confirmation")
	}
	return nil
}
