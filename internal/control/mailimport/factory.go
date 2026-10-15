package mailimport

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"

	transport "github.com/nakroteck/nakpanel/internal/mailimport"
	"github.com/nakroteck/nakpanel/internal/types"
)

type Agent interface {
	Do(context.Context, types.Request) (types.Response, error)
}
type RuntimeFactory struct {
	DB                    *sql.DB
	Secrets               SecretStore
	Agent                 Agent
	AllowedSourceNetworks []netip.Prefix
}

func (f *RuntimeFactory) Cleanup(ctx context.Context, job Job) error {
	if job.SourceKind != "maildir" {
		return nil
	}
	var result struct{}
	return callAgent(ctx, f.Agent, types.OpRemoveMaildirStage, types.RemoveMaildirStageReq{SubscriptionID: job.SubscriptionID, StagingID: job.StagingID, ManifestSHA256: job.ManifestSHA256}, &result)
}

func ParseSourceNetworks(value string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, errors.New("invalid mail import source CIDR")
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}
func sameIMAPAccount(ctx context.Context, sourceHost, sourceUser, targetHost, targetUser string) bool {
	if !strings.EqualFold(sourceUser, targetUser) {
		return false
	}
	if strings.EqualFold(sourceHost, targetHost) {
		return true
	}
	a, err := net.DefaultResolver.LookupNetIP(ctx, "ip", sourceHost)
	if err != nil {
		return false
	}
	b, err := net.DefaultResolver.LookupNetIP(ctx, "ip", targetHost)
	if err != nil {
		return false
	}
	for _, x := range a {
		for _, y := range b {
			if x.Unmap() == y.Unmap() {
				return true
			}
		}
	}
	return false
}

func (f *RuntimeFactory) secret(ctx context.Context, id, ref string) ([]byte, error) {
	if f.Secrets == nil {
		return nil, errors.New("mail credential store unavailable")
	}
	var name string
	if err := f.DB.QueryRowContext(ctx, `SELECT name FROM service_secrets WHERE scope='mail-import' AND secret_id=$1 AND metadata->>'import_id'=$2`, ref, id).Scan(&name); err != nil {
		return nil, errors.New("mail import credential unavailable")
	}
	value, _, err := f.Secrets.GetSecret(ctx, "mail-import", name)
	return value, err
}
func (f *RuntimeFactory) Open(ctx context.Context, job Job) (Source, Target, error) {
	var host string
	if err := f.DB.QueryRowContext(ctx, `SELECT mail_hostname FROM mail_settings WHERE id`).Scan(&host); err != nil || host == "" {
		return nil, nil, errors.New("server mail hostname is not configured")
	}
	if job.SourceKind == "imap" && sameIMAPAccount(ctx, job.SourceHost, job.SourceUser, host, job.Address) {
		return nil, nil, errors.New("source and destination must be different mailboxes")
	}
	password, err := f.secret(ctx, job.ID, job.TargetSecretID)
	if err != nil {
		return nil, nil, err
	}
	defer clear(password)
	target, err := transport.DialIMAP(ctx, transport.IMAPConfig{Host: host, Username: job.Address, Password: string(password)})
	if err != nil {
		return nil, nil, err
	}
	if job.SourceKind == "maildir" {
		return &maildirSource{agent: f.Agent, job: job}, target, nil
	}
	password, err = f.secret(ctx, job.ID, job.SourceSecretID)
	if err != nil {
		target.Close()
		return nil, nil, err
	}
	defer clear(password)
	source, err := transport.DialIMAP(ctx, transport.IMAPConfig{Host: job.SourceHost, Username: job.SourceUser, Password: string(password), AllowNetworks: f.AllowedSourceNetworks})
	if err != nil {
		target.Close()
		return nil, nil, err
	}
	return source, target, nil
}

type maildirSource struct {
	agent Agent
	job   Job
	known map[string]transport.Message
}

func (s *maildirSource) Close() error { return nil }
func callAgent(ctx context.Context, agent Agent, op string, input, output any) error {
	if agent == nil {
		return errors.New("mail import agent unavailable")
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return err
	}
	response, err := agent.Do(ctx, types.Request{ID: hex.EncodeToString(id), Op: op, Data: payload})
	if err != nil || !response.OK {
		return errors.New("mail import staging operation failed")
	}
	return json.Unmarshal(response.Data, output)
}
func (s *maildirSource) Discover(ctx context.Context) ([]transport.Folder, error) {
	folders := map[string]*transport.Folder{}
	s.known = map[string]transport.Message{}
	offset := 0
	for {
		var page types.InspectMaildirResult
		err := callAgent(ctx, s.agent, types.OpInspectMaildir, types.InspectMaildirReq{SubscriptionID: s.job.SubscriptionID, StagingID: s.job.StagingID, ManifestSHA256: s.job.ManifestSHA256, Offset: offset, Limit: 100}, &page)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Messages {
			if folders[entry.Folder] == nil {
				folders[entry.Folder] = &transport.Folder{Name: entry.Folder, Delimiter: "/"}
			}
			folders[entry.Folder].Messages = append(folders[entry.Folder].Messages, transport.Message{Identity: transport.MessageIdentity{Folder: entry.Folder, Key: entry.Key}, Flags: entry.Flags, Size: entry.Size, InternalDate: entry.InternalDate})
			s.known[entry.Key] = folders[entry.Folder].Messages[len(folders[entry.Folder].Messages)-1]
		}
		if page.NextOffset >= page.Total {
			break
		}
		if page.NextOffset <= offset {
			return nil, errors.New("invalid Maildir progress")
		}
		offset = page.NextOffset
	}
	out := []transport.Folder{}
	for _, folder := range folders {
		out = append(out, *folder)
	}
	return out, nil
}
func (s *maildirSource) Read(ctx context.Context, id transport.MessageIdentity) (transport.Message, error) {
	var body []byte
	hash := ""
	for {
		var chunk types.ReadMaildirMessageResult
		err := callAgent(ctx, s.agent, types.OpReadMaildirMessage, types.ReadMaildirMessageReq{SubscriptionID: s.job.SubscriptionID, StagingID: s.job.StagingID, ManifestSHA256: s.job.ManifestSHA256, Key: id.Key, Offset: int64(len(body)), Limit: 128 << 10}, &chunk)
		if err != nil {
			return transport.Message{}, err
		}
		if hash != "" && chunk.SHA256 != hash {
			return transport.Message{}, transport.ErrSourceChanged
		}
		hash = chunk.SHA256
		body = append(body, chunk.Data...)
		if len(body) > transport.MaxMessageBytes {
			return transport.Message{}, errors.New("Maildir message exceeds limit")
		}
		if chunk.EOF {
			break
		}
		if len(chunk.Data) == 0 {
			return transport.Message{}, errors.New("empty Maildir read")
		}
	}
	if transport.ContentHash(body) != hash {
		return transport.Message{}, transport.ErrSourceChanged
	}
	if msg, ok := s.known[id.Key]; ok && msg.Identity.String() == id.String() {
		msg.Body = body
		return msg, nil
	}
	return transport.Message{}, transport.ErrSourceChanged
}
