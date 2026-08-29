package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

const (
	maxMailQueueResponseBytes = 4 << 20
	maxMailQueueRead          = 200
)

var stalwartQueueIDRE = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

type stalwartQueueMessage struct {
	ID         json.Number           `json:"id"`
	ReturnPath string                `json:"return_path"`
	Domains    []stalwartQueueDomain `json:"domains"`
	Created    string                `json:"created"`
	Size       int64                 `json:"size"`
}

type stalwartQueueDomain struct {
	Name       string                   `json:"name"`
	Status     json.RawMessage          `json:"status"`
	Recipients []stalwartQueueRecipient `json:"recipients"`
	RetryNum   int                      `json:"retry_num"`
	NextRetry  string                   `json:"next_retry"`
	Expires    string                   `json:"expires"`
}

type stalwartQueueRecipient struct {
	Address string          `json:"address"`
	Status  json.RawMessage `json:"status"`
}

// QueryMailQueue reads bounded delivery metadata from Stalwart v0.11's
// management API. It never fetches message blobs or accepts raw expressions.
func (p *MailProvisioner) QueryMailQueue(ctx context.Context, req types.MailQueueQueryReq) (types.MailQueueQueryResult, error) {
	req.State = strings.ToLower(strings.TrimSpace(req.State))
	req.SenderDomain = strings.ToLower(strings.TrimSpace(req.SenderDomain))
	req.RecipientDomain = strings.ToLower(strings.TrimSpace(req.RecipientDomain))
	if err := validateMailQueueQuery(req); err != nil {
		return types.MailQueueQueryResult{}, err
	}

	query := url.Values{"values": {"1"}, "limit": {strconv.Itoa(maxMailQueueRead)}, "max-total": {"201"}}
	if req.SenderDomain != "" {
		query.Set("from", req.SenderDomain)
	}
	if req.RecipientDomain != "" {
		query.Set("to", req.RecipientDomain)
	}
	if req.OlderThanMins > 0 {
		query.Set("before", time.Now().UTC().Add(-time.Duration(req.OlderThanMins)*time.Minute).Format(time.RFC3339))
	}

	body, err := p.stalwartAdminGET(ctx, "/api/queue/messages?"+query.Encode())
	if err != nil {
		return types.MailQueueQueryResult{}, err
	}
	var payload struct {
		Data struct {
			Items []stalwartQueueMessage `json:"items"`
			Total int                    `json:"total"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return types.MailQueueQueryResult{}, fmt.Errorf("decode Stalwart queue metadata: %w", err)
	}

	result := types.MailQueueQueryResult{
		Messages:  make([]types.MailQueueMessage, 0, min(req.Limit, len(payload.Data.Items))),
		Truncated: payload.Data.Total > len(payload.Data.Items),
		CheckedAt: time.Now().UTC(),
	}
	for _, raw := range payload.Data.Items {
		message := normalizeStalwartQueueMessage(raw)
		if !mailQueueMessageMatches(message, req) {
			continue
		}
		if len(result.Messages) == req.Limit {
			result.Truncated = true
			continue
		}
		result.Messages = append(result.Messages, message)
	}
	result.Total = len(result.Messages)
	return result, nil
}

func (p *MailProvisioner) InspectQueuedMail(ctx context.Context, req types.InspectQueuedMailReq) (types.MailQueueMessage, error) {
	req.MessageID = strings.TrimSpace(req.MessageID)
	if !stalwartQueueIDRE.MatchString(req.MessageID) {
		return types.MailQueueMessage{}, errors.New("queued mail id is invalid")
	}
	if _, err := strconv.ParseUint(req.MessageID, 10, 64); err != nil {
		return types.MailQueueMessage{}, errors.New("queued mail id is invalid")
	}
	body, err := p.stalwartAdminGET(ctx, "/api/queue/messages/"+req.MessageID)
	if err != nil {
		return types.MailQueueMessage{}, err
	}
	var payload struct {
		Data stalwartQueueMessage `json:"data"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return types.MailQueueMessage{}, fmt.Errorf("decode Stalwart queued message metadata: %w", err)
	}
	result := normalizeStalwartQueueMessage(payload.Data)
	if result.ID == "" {
		result.ID = req.MessageID
	}
	return result, nil
}

func (p *MailProvisioner) stalwartAdminGET(ctx context.Context, path string) ([]byte, error) {
	secret, err := os.ReadFile(p.adminSecretPath)
	if err != nil {
		return nil, fmt.Errorf("read Stalwart admin secret: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.managementURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth("admin", strings.TrimSpace(string(secret)))
	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query Stalwart mail queue: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMailQueueResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMailQueueResponseBytes {
		return nil, errors.New("Stalwart queue response exceeded the configured limit")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Stalwart queue query failed: status %d", response.StatusCode)
	}
	return body, nil
}

func validateMailQueueQuery(req types.MailQueueQueryReq) error {
	if req.Limit < 1 || req.Limit > maxMailQueueRead {
		return errors.New("mail queue limit must be between 1 and 200")
	}
	if req.OlderThanMins < 0 || req.OlderThanMins > 60*24*90 {
		return errors.New("older_than_minutes must be between 0 and 129600")
	}
	if req.State != "" && req.State != types.MailQueueStateQueued && req.State != types.MailQueueStateDeferred {
		return errors.New("mail queue state is unsupported")
	}
	for name, domain := range map[string]string{"sender_domain": req.SenderDomain, "recipient_domain": req.RecipientDomain} {
		if domain != "" && !validMailQueueDomain(domain) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

func validMailQueueDomain(domain string) bool {
	if len(domain) > 253 || strings.HasSuffix(domain, ".") || strings.ContainsAny(domain, "/\\@?#[]\x00\r\n\t ") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func normalizeStalwartQueueMessage(raw stalwartQueueMessage) types.MailQueueMessage {
	result := types.MailQueueMessage{
		ID: raw.ID.String(), ReturnPath: raw.ReturnPath, SizeBytes: raw.Size,
		Domains: make([]types.MailQueueDomain, 0, len(raw.Domains)),
	}
	result.CreatedAt, _ = time.Parse(time.RFC3339, raw.Created)
	for _, rawDomain := range raw.Domains {
		domain := types.MailQueueDomain{
			Name: rawDomain.Name, Status: stalwartQueueStatus(rawDomain.Status), RetryCount: rawDomain.RetryNum,
			Recipients: make([]types.MailQueueRecipient, 0, len(rawDomain.Recipients)),
		}
		domain.NextRetry = optionalRFC3339(rawDomain.NextRetry)
		domain.ExpiresAt = optionalRFC3339(rawDomain.Expires)
		for _, rawRecipient := range rawDomain.Recipients {
			domain.Recipients = append(domain.Recipients, types.MailQueueRecipient{
				Address: rawRecipient.Address, Status: stalwartQueueStatus(rawRecipient.Status),
			})
		}
		result.Domains = append(result.Domains, domain)
		if domain.Status == "temp_fail" {
			result.State = types.MailQueueStateDeferred
		} else if result.State == "" && domain.Status == "scheduled" {
			result.State = types.MailQueueStateQueued
		}
	}
	if result.State == "" {
		result.State = types.MailQueueStateQueued
	}
	return result
}

func stalwartQueueStatus(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.ToLower(text)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) == nil {
		for key := range object {
			return strings.ToLower(key)
		}
	}
	return "unknown"
}

func optionalRFC3339(value string) *time.Time {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &parsed
}

func mailQueueMessageMatches(message types.MailQueueMessage, req types.MailQueueQueryReq) bool {
	if req.State != "" && message.State != req.State {
		return false
	}
	if req.SenderDomain != "" && addressDomain(message.ReturnPath) != req.SenderDomain {
		return false
	}
	if req.RecipientDomain != "" {
		found := false
		for _, domain := range message.Domains {
			if domain.Name == req.RecipientDomain {
				found = true
				break
			}
			for _, recipient := range domain.Recipients {
				if addressDomain(recipient.Address) == req.RecipientDomain {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	if req.OlderThanMins > 0 && (message.CreatedAt.IsZero() || message.CreatedAt.After(time.Now().UTC().Add(-time.Duration(req.OlderThanMins)*time.Minute))) {
		return false
	}
	return true
}

func addressDomain(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 || at == len(address)-1 {
		return ""
	}
	return strings.ToLower(address[at+1:])
}
