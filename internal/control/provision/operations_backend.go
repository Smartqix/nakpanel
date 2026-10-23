package provision

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

type OperationsAgent interface {
	Ping(context.Context) (types.Response, error)
	InspectServer(context.Context) (types.ServerInventory, error)
	RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error)
	ReadBackupChunk(context.Context, types.ReadBackupChunkReq) (types.ReadBackupChunkResult, error)
	InspectSiteReadiness(context.Context, types.InspectSiteReadinessReq) (types.SiteReadinessResult, error)
	MailStatus(context.Context) (types.MailServerStatus, error)
}
type operationArchive struct {
	Databases      []string
	ID             int64
	Path, Checksum string
	Size           int64
	CompletedAt    *time.Time
}
type operationIntent struct {
	Databases                                         []string
	DataScopeHash                                     string
	Resource                                          operations.Resource
	SiteID, SubscriptionID, CustomerID, OwnerID       int64
	Domain, Username, Docroot, PHPVersion             string
	Hash                                              string
	Revision                                          int64
	Policy                                            types.HostingPolicy
	Archive                                           operationArchive
	SiteCreatedAt                                     time.Time
	TLSExpiresAt                                      *time.Time
	WebmailHostname                                   string
	WebmailReady                                      bool
	MailReady                                         bool
	RawSite, RawSubscription, RawEntitlement, RawMail string
	RawCustomer, RawProvider                          string
}

// snapshotOperationIntentTx reloads identity, policy and observed source state
// under the same mutation fences used by existing provisioning. Private source
// JSON is hashed here and never included in a browser response or receipt.
func (m *OperationsManager) snapshotOperationIntentTx(ctx context.Context, tx *sql.Tx, r operations.Resource) (operationIntent, error) {
	in := operationIntent{Resource: r}
	if r.Kind == operations.ResourceServer {
		var ready bool
		err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(md) ORDER BY id),'[]'::jsonb)::text,COALESCE(bool_and(NOT enabled OR convergence_status='in_sync'),true) FROM mail_domains md`).Scan(&in.RawMail, &ready)
		if err != nil {
			return in, err
		}
		in.MailReady = ready
		in.finishHash()
		return in, nil
	}
	if r.Kind != operations.ResourceSite {
		return in, operations.ErrInvalid
	}
	if err := controlquota.LockSiteMutationTx(ctx, tx, r.ID); err != nil {
		return in, err
	}
	var siteStatus, desiredStatus, subStatus, customerStatus, providerStatus string
	var allocation bool
	err := tx.QueryRowContext(ctx, `SELECT to_jsonb(s)::text,to_jsonb(sub)::text,to_jsonb(e)::text,to_jsonb(c)::text,COALESCE(to_jsonb(r)::text,'null'),s.id,s.subscription_id,s.customer_id,s.owner_user_id,s.domain,s.username,s.document_root,COALESCE(NULLIF(s.desired_php_version,''),s.php_version),s.created_at,s.tls_expires_at,s.status,s.desired_status,sub.status,c.status,COALESCE(r.status,'active'),(c.reseller_id IS NULL OR EXISTS(SELECT 1 FROM reseller_subscriptions rs WHERE rs.reseller_id=c.reseller_id AND rs.status='active'))
 FROM sites s JOIN subscriptions sub ON sub.id=s.subscription_id JOIN customers c ON c.id=sub.customer_id JOIN subscription_entitlements e ON e.subscription_id=sub.id LEFT JOIN reseller_accounts r ON r.id=c.reseller_id WHERE s.id=$1 FOR UPDATE OF s,sub,c,e`, r.ID).Scan(&in.RawSite, &in.RawSubscription, &in.RawEntitlement, &in.RawCustomer, &in.RawProvider, &in.SiteID, &in.SubscriptionID, &in.CustomerID, &in.OwnerID, &in.Domain, &in.Username, &in.Docroot, &in.PHPVersion, &in.SiteCreatedAt, &in.TLSExpiresAt, &siteStatus, &desiredStatus, &subStatus, &customerStatus, &providerStatus, &allocation)
	if err != nil {
		return in, err
	}
	if siteStatus != "active" || desiredStatus != "active" || subStatus != "active" || customerStatus != "active" || providerStatus != "active" || !allocation {
		return in, controlquota.ErrNoActiveSubscription
	}
	in.Policy, err = controlquota.EffectiveSitePolicyTx(ctx, tx, in.SiteID)
	if err != nil {
		return in, err
	}
	in.Databases, err = selectActiveSubscriptionDatabases(ctx, tx, in.SubscriptionID)
	if err != nil {
		return in, err
	}
	var archiveDatabases pq.StringArray
	err = tx.QueryRowContext(ctx, `SELECT id,archive_path,checksum_sha256,size_bytes,completed_at,database_names FROM backups WHERE site_id=$1 AND subscription_id=$2 AND customer_id=$3 AND owner_user_id=$4 AND status='active' ORDER BY completed_at DESC NULLS LAST,id DESC LIMIT 1`, in.SiteID, in.SubscriptionID, in.CustomerID, in.OwnerID).Scan(&in.Archive.ID, &in.Archive.Path, &in.Archive.Checksum, &in.Archive.Size, &in.Archive.CompletedAt, &archiveDatabases)
	in.Archive.Databases = append([]string(nil), archiveDatabases...)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return in, err
	}
	var mailReady bool
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(md) ORDER BY id),'[]'::jsonb)::text,COALESCE(bool_and(NOT enabled OR convergence_status='in_sync'),true) FROM mail_domains md WHERE site_id=$1`, in.SiteID).Scan(&in.RawMail, &mailReady); err != nil {
		return in, err
	}
	in.MailReady = mailReady
	var hostname, status string
	err = tx.QueryRowContext(ctx, `SELECT hostname,status FROM webmail_hosts WHERE site_id=$1 ORDER BY id DESC LIMIT 1`, in.SiteID).Scan(&hostname, &status)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return in, err
	}
	in.WebmailHostname = hostname
	in.WebmailReady = status == "active"
	in.finishHash()
	return in, nil
}
func (in *operationIntent) finishHash() {
	scopeData, _ := json.Marshal([]any{in.Resource, in.SubscriptionID, in.CustomerID, in.OwnerID, in.Domain, in.Username, in.Docroot, in.Databases})
	scopeSum := sha256.Sum256(scopeData)
	in.DataScopeHash = hex.EncodeToString(scopeSum[:])
	data, _ := json.Marshal(struct {
		Resource                                                  operations.Resource
		Site, Subscription, Entitlement, Mail, Customer, Provider string
		Policy                                                    types.HostingPolicy
		Archive                                                   operationArchive
		DataScopeHash                                             string
		Host                                                      string
		WebmailReady                                              bool
	}{in.Resource, in.RawSite, in.RawSubscription, in.RawEntitlement, in.RawMail, in.RawCustomer, in.RawProvider, in.Policy, in.Archive, in.DataScopeHash, in.WebmailHostname, in.WebmailReady})
	sum := sha256.Sum256(data)
	in.Hash = hex.EncodeToString(sum[:])
	in.Revision = int64(binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff)
}

func (m *OperationsManager) probeOperation(ctx context.Context, i operations.Issue, in operationIntent) (operations.VerificationReceipt, error) {
	r := operations.VerificationReceipt{IntentHash: in.Hash, SourceID: in.SiteID}
	if m.agent == nil {
		return r, errors.New("readiness inspection is unavailable")
	}
	switch i.Kind {
	case "backup":
		if !in.Policy.Permissions.Backups || !in.Policy.Backups.Enabled || in.Archive.ID == 0 || in.Archive.CompletedAt == nil {
			return r, errors.New("a current completed archive is required")
		}
		if !slices.Equal(normalizedDatabaseNames(in.Archive.Databases), normalizedDatabaseNames(in.Databases)) {
			return r, errors.New("the archive does not cover the current database scope")
		}
		due, err := backupDeadline(in.Policy.Backups.Schedule, *in.Archive.CompletedAt)
		if err != nil || time.Now().UTC().After(due) {
			return r, errors.New("backup protection is still overdue")
		}
		result, err := m.agent.ReadBackupChunk(ctx, types.ReadBackupChunkReq{BackupID: in.Archive.ID, SubscriptionID: in.SubscriptionID, Domain: in.Domain, ArchivePath: in.Archive.Path, SHA256: in.Archive.Checksum, Offset: 0, Limit: 1})
		if err != nil {
			return r, errors.New("managed archive verification failed")
		}
		if result.BackupID != in.Archive.ID || result.SHA256 != in.Archive.Checksum || result.Size != in.Archive.Size || result.Size <= 0 || len(result.Data) != 1 {
			return r, errors.New("managed archive verification did not match current intent")
		}
		r.Source = "archive_checksum"
		r.SourceID = in.Archive.ID
		r.Checksum = result.SHA256
		r.SizeBytes = result.Size
		r.Summary = "Managed archive checksum and size verified. A restore has not been tested."
	case "tls":
		if !in.Policy.Permissions.TLS {
			return r, errors.New("TLS is disabled by policy")
		}
		cert, err := probeLocalTLS(ctx, in.Domain)
		if err != nil || !cert.NotAfter.After(time.Now().Add(14*24*time.Hour)) {
			return r, errors.New("a valid trusted local certificate outside the expiry warning window is required")
		}
		r.Source = "local_tls"
		r.Summary = "Local HTTPS hostname and trusted certificate verified. Public DNS was not checked."
	case "hosting":
		if !in.Policy.Permissions.Hosting {
			return r, errors.New("hosting is disabled by policy")
		}
		capabilities, err := m.agent.RuntimeCapabilities(ctx)
		if err != nil {
			return r, errors.New("hosting runtime validation is unavailable")
		}
		for _, required := range []string{"8.3", "8.4", "8.5"} {
			ready := false
			for _, runtime := range capabilities.PHPRuntimes {
				if runtime.Version == required {
					ready = runtime.Ready
				}
			}
			if !ready {
				return r, errors.New("the required hosting PHP runtime profile is not ready")
			}
		}
		result, err := m.agent.InspectSiteReadiness(ctx, types.InspectSiteReadinessReq{SiteID: in.SiteID, SubscriptionID: in.SubscriptionID, Username: in.Username, Domain: in.Domain, PHPVersion: in.PHPVersion})
		if err != nil || !result.Ready || !freshOperationTime(result.CheckedAt) {
			return r, errors.New("the website's isolated runtime could not be verified")
		}
		r.Source = "local_hosting"
		r.Summary = "Managed vhost, tenant PHP configuration and isolated FPM socket verified."
	case "mail":
		if in.Resource.Kind == operations.ResourceSite && (!in.Policy.Permissions.Mail || !in.Policy.Mail.Enabled) {
			return r, errors.New("mail is disabled by policy")
		}
		if !in.MailReady {
			return r, errors.New("mail settings have not converged")
		}
		status, err := m.agent.MailStatus(ctx)
		if err != nil || status.State != "active" || status.LastError != "" || !freshOperationTime(status.CheckedAt) || !slices.Contains(status.Listeners, 25) || !slices.Contains(status.Listeners, 993) {
			return r, errors.New("local mail runtime could not be verified")
		}
		r.Source = "mail_runtime"
		r.Summary = "Local mail service and SMTP/IMAP listeners verified. External delivery was not tested."
		if in.WebmailHostname != "" && in.Policy.Mail.Webmail {
			if !in.WebmailReady || probeLocalWebmail(ctx, in.WebmailHostname) != nil {
				return r, errors.New("trusted HTTPS webmail login could not be verified")
			}
			r.Source = "webmail_https"
			r.Summary = "Local mail service and trusted HTTPS webmail login verified. External delivery was not tested."
		}
	default:
		return r, errors.New("independent verification is unavailable for this operation; review its resource settings")
	}
	r.ObservedAt = time.Now().UTC()
	return r, nil
}

func probeLocalTLS(ctx context.Context, hostname string) (*x509.Certificate, error) {
	if site.ValidateDomain(hostname) != nil || hostname != site.NormalizeDomain(hostname) {
		return nil, operations.ErrInvalid
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}}
	c, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:443")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	connection := c.(*tls.Conn)
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("TLS peer certificate is unavailable")
	}
	return state.PeerCertificates[0], nil
}

func probeLocalWebmail(ctx context.Context, hostname string) error {
	if site.ValidateDomain(hostname) != nil || hostname != site.NormalizeDomain(hostname) {
		return operations.ErrInvalid
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:443")
	}, TLSClientConfig: &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+"/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	if err != nil {
		return err
	}
	text := strings.ToLower(string(body))
	if response.StatusCode != http.StatusOK || !strings.Contains(text, "roundcube") || !strings.Contains(text, "login-form") {
		return errors.New("expected webmail login is unavailable")
	}
	return nil
}

func freshOperationTime(at time.Time) bool {
	now := time.Now()
	return !at.IsZero() && !at.Before(now.Add(-time.Minute)) && !at.After(now.Add(time.Minute))
}
