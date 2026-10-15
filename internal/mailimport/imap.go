package mailimport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

type IMAPConfig struct {
	Host               string
	Port               int
	Username, Password string
	RootCAs            *x509.CertPool
	AllowNetworks      []netip.Prefix
}
type IMAP struct {
	client *imapclient.Client
	mutex  sync.Mutex
}

func DialIMAP(ctx context.Context, cfg IMAPConfig) (*IMAP, error) {
	if cfg.Port == 0 {
		cfg.Port = 993
	}
	if cfg.Port != 993 {
		return nil, errors.New("IMAP requires implicit TLS on port 993")
	}
	return dialIMAP(ctx, cfg, cfg.Port)
}
func allowedIP(ip netip.Addr, allowed []netip.Prefix) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		for _, p := range allowed {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	return ip.IsGlobalUnicast()
}
func dialIMAP(ctx context.Context, cfg IMAPConfig, port int) (*IMAP, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", cfg.Host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("cannot resolve the IMAP hostname")
	}
	for _, ip := range addresses {
		if !allowedIP(ip, cfg.AllowNetworks) {
			return nil, errors.New("IMAP hostname resolves to a prohibited address")
		}
	}
	var conn net.Conn
	for _, ip := range addresses {
		conn, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("cannot connect to the IMAP server")
	}
	secure := tls.Client(conn, &tls.Config{ServerName: cfg.Host, RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12})
	if err = secure.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, errors.New("IMAP TLS certificate validation failed")
	}
	c := imapclient.New(secure, nil)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err = c.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		c.Close()
		return nil, errors.New("IMAP authentication failed")
	}
	return &IMAP{client: c}, nil
}
func (c *IMAP) Close() error { return c.client.Close() }
func (c *IMAP) AvailableBytes(ctx context.Context) (int64, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	defer c.bounded(ctx)()
	selected, err := c.client.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return 0, errors.New("destination mailbox is unavailable")
	}
	wildcard := false
	for _, flag := range selected.PermanentFlags {
		wildcard = wildcard || flag == imap.FlagWildcard
	}
	if !wildcard || (!c.client.Caps().Has(imap.CapUIDPlus) && !c.client.Caps().Has(imap.CapIMAP4rev2)) {
		return 0, errors.New("destination lacks durable receipt support")
	}
	if !c.client.Caps().Has(imap.CapQuota) {
		return 0, errors.New("destination cannot report mailbox quota")
	}
	quotas, err := c.client.GetQuotaRoot("INBOX").Wait()
	if err != nil {
		return 0, errors.New("destination quota is unavailable")
	}
	remaining := int64(-1)
	for _, quota := range quotas {
		if storage, ok := quota.Resources[imap.QuotaResourceStorage]; ok {
			free := max(int64(0), storage.Limit-storage.Usage) * 1024
			if remaining < 0 || free < remaining {
				remaining = free
			}
		}
	}
	return remaining, nil
}
func (c *IMAP) bounded(ctx context.Context) func() {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	stop := context.AfterFunc(bounded, func() { c.Close() })
	return func() { stop(); cancel() }
}
func (c *IMAP) Discover(ctx context.Context) ([]Folder, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	defer c.bounded(ctx)()
	list, err := c.client.List("", "*", nil).Collect()
	if err != nil {
		return nil, errors.New("cannot list source folders")
	}
	if len(list) > 1000 {
		return nil, errors.New("source exceeds the 1000-folder import limit")
	}
	var folders []Folder
	total := 0
	for _, entry := range list {
		skip := false
		for _, attr := range entry.Attrs {
			if attr == imap.MailboxAttrNoSelect {
				skip = true
			}
		}
		if skip {
			continue
		}
		selected, err := c.client.Select(entry.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil {
			return nil, errors.New("cannot inspect a source folder")
		}
		f := Folder{Name: entry.Mailbox, Delimiter: string(entry.Delim), UIDValidity: selected.UIDValidity}
		for _, attr := range entry.Attrs {
			if specialUse(string(attr)) {
				f.SpecialUse = string(attr)
			}
		}
		if selected.NumMessages > 0 {
			var all imap.UIDSet
			all.AddRange(1, 0)
			cmd := c.client.Fetch(all, &imap.FetchOptions{UID: true, Flags: true, InternalDate: true, RFC822Size: true})
			for data := cmd.Next(); data != nil; data = cmd.Next() {
				b, err := data.Collect()
				if err != nil {
					cmd.Close()
					return nil, errors.New("cannot read source message metadata")
				}
				total++
				if total > 100000 {
					c.Close()
					return nil, errors.New("source exceeds the 100000-message import limit")
				}
				if b.RFC822Size > MaxMessageBytes {
					cmd.Close()
					return nil, errors.New("source contains a message larger than 64 MiB")
				}
				m := Message{Identity: MessageIdentity{Folder: f.Name, UIDValidity: f.UIDValidity, UID: uint32(b.UID)}, InternalDate: b.InternalDate, Size: b.RFC822Size}
				for _, flag := range b.Flags {
					if flag != imap.Flag(`\Recent`) {
						m.Flags = append(m.Flags, string(flag))
					}
				}
				f.Messages = append(f.Messages, m)
			}
			if err = cmd.Close(); err != nil {
				return nil, errors.New("source discovery interrupted")
			}
		}
		folders = append(folders, f)
	}
	return folders, nil
}
func specialUse(value string) bool {
	switch strings.ToLower(value) {
	case `\sent`, `\drafts`, `\trash`, `\junk`, `\archive`, `\all`, `\flagged`, `\important`:
		return true
	}
	return false
}
func (c *IMAP) EnsureFolderWithRole(ctx context.Context, name, role string) error {
	if !specialUse(role) {
		return c.EnsureFolder(ctx, name)
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	defer c.bounded(ctx)()
	items, err := c.client.List("", name, nil).Collect()
	if err != nil {
		return errors.New("cannot inspect destination folder roles")
	}
	for _, item := range items {
		if item.Mailbox != name {
			continue
		}
		for _, attr := range item.Attrs {
			if strings.EqualFold(string(attr), role) {
				return nil
			}
		}
		return errors.New("destination folder has a different special-use role; review the mapping")
	}
	if !c.client.Caps().Has(imap.CapCreateSpecialUse) {
		return errors.New("destination cannot preserve special-use folder roles")
	}
	if err = c.client.Create(name, &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttr(role)}}).Wait(); err != nil {
		return errors.New("cannot create destination special-use folder")
	}
	return nil
}
func (c *IMAP) Read(ctx context.Context, id MessageIdentity) (Message, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	defer c.bounded(ctx)()
	selected, err := c.client.Select(id.Folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return Message{}, errors.New("cannot select message folder")
	}
	if selected.UIDValidity != id.UIDValidity {
		return Message{}, ErrSourceChanged
	}
	section := &imap.FetchItemBodySection{Peek: true}
	cmd := c.client.Fetch(imap.UIDSetNum(imap.UID(id.UID)), &imap.FetchOptions{UID: true, Flags: true, InternalDate: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{section}})
	msg := Message{Identity: id}
	found := false
	for data := cmd.Next(); data != nil; data = cmd.Next() {
		found = true
		for item := data.Next(); item != nil; item = data.Next() {
			switch v := item.(type) {
			case imapclient.FetchItemDataBodySection:
				if v.Literal == nil {
					continue
				}
				msg.Body, err = io.ReadAll(io.LimitReader(v.Literal, MaxMessageBytes+1))
				if err != nil || len(msg.Body) > MaxMessageBytes {
					c.Close()
					return Message{}, errors.New("message body exceeds the safe import limit")
				}
			case imapclient.FetchItemDataFlags:
				for _, flag := range v.Flags {
					if flag != imap.Flag(`\Recent`) {
						msg.Flags = append(msg.Flags, string(flag))
					}
				}
			case imapclient.FetchItemDataInternalDate:
				msg.InternalDate = v.Time
			case imapclient.FetchItemDataRFC822Size:
				msg.Size = v.Size
			}
		}
	}
	if err = cmd.Close(); err != nil || !found {
		return Message{}, errors.New("source message could not be read")
	}
	return msg, nil
}
func (c *IMAP) EnsureFolder(ctx context.Context, name string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	defer c.bounded(ctx)()
	if _, err := c.client.Select(name, &imap.SelectOptions{ReadOnly: true}).Wait(); err == nil {
		return nil
	}
	if err := c.client.Create(name, nil).Wait(); err != nil {
		return errors.New("cannot create destination folder")
	}
	return nil
}
func validToken(token string) bool {
	if !strings.HasPrefix(token, "npimport_") || len(token) < 40 || len(token) > 80 {
		return false
	}
	for _, c := range strings.TrimPrefix(token, "npimport_") {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func appendOutcomeError(error) error { return ErrUncertain }
func (c *IMAP) Append(ctx context.Context, msg Message, token string) (Receipt, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	defer c.bounded(ctx)()
	if !validToken(token) || len(msg.Body) > MaxMessageBytes {
		return Receipt{}, errors.New("invalid import message or receipt")
	}
	selected, err := c.client.Select(msg.Identity.Folder, nil).Wait()
	if err != nil {
		return Receipt{}, errors.New("cannot select destination folder")
	}
	if !c.client.Caps().Has(imap.CapUIDPlus) && !c.client.Caps().Has(imap.CapIMAP4rev2) {
		return Receipt{}, errors.New("destination must support UIDPLUS")
	}
	wildcard := false
	allowed := map[string]bool{}
	for _, f := range selected.PermanentFlags {
		allowed[strings.ToLower(string(f))] = true
		if f == imap.FlagWildcard {
			wildcard = true
		}
	}
	if !wildcard {
		return Receipt{}, errors.New("destination cannot preserve durable import receipt keywords")
	}
	flags := []imap.Flag{imap.Flag(token)}
	for _, f := range msg.Flags {
		if strings.EqualFold(f, `\Recent`) {
			continue
		}
		if !allowed[strings.ToLower(f)] && strings.HasPrefix(f, "\\") {
			return Receipt{}, errors.New("destination does not support a source message flag")
		}
		flags = append(flags, imap.Flag(f))
	}
	cmd := c.client.Append(msg.Identity.Folder, int64(len(msg.Body)), &imap.AppendOptions{Flags: flags, Time: msg.InternalDate})
	if _, err = cmd.Write(msg.Body); err != nil {
		return Receipt{}, appendOutcomeError(err)
	}
	if err = cmd.Close(); err != nil {
		return Receipt{}, appendOutcomeError(err)
	}
	data, err := cmd.Wait()
	if err != nil {
		return Receipt{}, appendOutcomeError(err)
	}
	if data.UID == 0 || data.UIDValidity == 0 {
		return Receipt{}, ErrUncertain
	}
	return Receipt{msg.Identity.Folder, uint32(data.UID), data.UIDValidity}, nil
}
func (c *IMAP) FindReceipt(ctx context.Context, folder, token string) ([]Receipt, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	defer c.bounded(ctx)()
	if !validToken(token) {
		return nil, errors.New("invalid import receipt")
	}
	selected, err := c.client.Select(folder, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return nil, errors.New("cannot inspect destination receipt")
	}
	data, err := c.client.UIDSearch(&imap.SearchCriteria{Flag: []imap.Flag{imap.Flag(token)}}, nil).Wait()
	if err != nil {
		return nil, errors.New("cannot reconcile destination receipt")
	}
	out := []Receipt{}
	for _, uid := range data.AllUIDs() {
		out = append(out, Receipt{folder, uint32(uid), selected.UIDValidity})
	}
	return out, nil
}
