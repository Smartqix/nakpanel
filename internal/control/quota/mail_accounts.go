package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

// Mailboxes and aliases are read live by Stalwart through the stalwart_*
// database views, so mutations here take effect without an agent round-trip.
// Every statement is scoped to the owning subscription through mail_domains:
// the tenant boundary lives in the SQL itself, not in the handlers above it.

var mailLocalPartRE = regexp.MustCompile("^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")

const (
	minMailboxPasswordLength = 12
	maxAliasDestinations     = 20
)

func (s *SQLStore) UpsertMailbox(ctx context.Context, subscriptionID, actorID int64, input types.MailboxInput) (int64, error) {
	input.LocalPart = strings.ToLower(strings.TrimSpace(input.LocalPart))
	if input.MailDomainID <= 0 || !mailLocalPartRE.MatchString(input.LocalPart) {
		return 0, errors.New("invalid mailbox address")
	}
	passwordHash := ""
	if strings.TrimSpace(input.Password) != "" {
		if len(input.Password) < minMailboxPasswordLength {
			return 0, fmt.Errorf("mailbox password must be at least %d characters", minMailboxPasswordLength)
		}
		var err error
		if passwordHash, err = auth.HashPassword(input.Password, auth.DefaultPasswordParams); err != nil {
			return 0, err
		}
	}
	if input.ID == 0 && passwordHash == "" {
		return 0, errors.New("a password is required for a new mailbox")
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Mail || !policy.Mail.Enabled {
			return 0, errors.New("mail is disabled by the subscription policy")
		}
		if err := ensureMailDomainBelongsTx(ctx, tx, subscriptionID, input.MailDomainID); err != nil {
			return 0, err
		}
		if input.ID == 0 {
			if err := enforceMailCountTx(ctx, tx, "mailboxes", subscriptionID, policy.Resources.MaxMailboxes); err != nil {
				return 0, err
			}
		}
		quota := input.QuotaMB
		if quota <= 0 {
			quota = -1
		}
		if limit := policy.Mail.MailboxQuotaMB; limit > 0 && (quota == -1 || quota > limit) {
			quota = limit
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO mailboxes(id,mail_domain_id,local_part,password_hash,quota_mb,enabled)
VALUES(CASE WHEN $1=0 THEN nextval('mailboxes_id_seq') ELSE $1 END,$2,$3,$4,$5,$6)
ON CONFLICT(id) DO UPDATE SET local_part=EXCLUDED.local_part,password_hash=CASE WHEN EXCLUDED.password_hash='' THEN mailboxes.password_hash ELSE EXCLUDED.password_hash END,quota_mb=EXCLUDED.quota_mb,enabled=EXCLUDED.enabled,updated_at=now()
WHERE mailboxes.mail_domain_id=EXCLUDED.mail_domain_id RETURNING id`,
			input.ID, input.MailDomainID, input.LocalPart, passwordHash, quota, input.Enabled).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			err = errors.New("mailbox does not belong to the subscription")
		}
		return id, err
	})
}

func (s *SQLStore) UpsertMailAlias(ctx context.Context, subscriptionID, actorID int64, input types.MailAliasInput) (int64, error) {
	input.LocalPart = strings.ToLower(strings.TrimSpace(input.LocalPart))
	if input.MailDomainID <= 0 || !mailLocalPartRE.MatchString(input.LocalPart) {
		return 0, errors.New("invalid alias address")
	}
	destinations := make([]string, 0, len(input.Destinations))
	seen := make(map[string]bool, len(input.Destinations))
	for _, destination := range input.Destinations {
		destination = strings.ToLower(strings.TrimSpace(destination))
		if destination == "" || seen[destination] {
			continue
		}
		local, domain, ok := strings.Cut(destination, "@")
		if !ok || !mailLocalPartRE.MatchString(local) || site.ValidateDomain(domain) != nil {
			return 0, fmt.Errorf("invalid alias destination %q", destination)
		}
		seen[destination] = true
		destinations = append(destinations, destination)
	}
	if len(destinations) == 0 || len(destinations) > maxAliasDestinations {
		return 0, fmt.Errorf("an alias needs between 1 and %d destination mailboxes", maxAliasDestinations)
	}
	return s.upsertAccountService(ctx, subscriptionID, func(tx *sql.Tx, policy types.HostingPolicy) (int64, error) {
		if !policy.Permissions.Mail || !policy.Mail.Enabled {
			return 0, errors.New("mail is disabled by the subscription policy")
		}
		if err := ensureMailDomainBelongsTx(ctx, tx, subscriptionID, input.MailDomainID); err != nil {
			return 0, err
		}
		if input.ID == 0 {
			// No plan knob exists for aliases yet, so an unset alias limit
			// inherits the mailbox limit instead of reading 0 as disabled.
			limit := policy.Resources.MaxMailAliases
			if limit == 0 {
				limit = policy.Resources.MaxMailboxes
			}
			if err := enforceMailCountTx(ctx, tx, "mail_aliases", subscriptionID, limit); err != nil {
				return 0, err
			}
		}
		for _, destination := range destinations {
			if err := ensureAliasDestinationTx(ctx, tx, subscriptionID, destination); err != nil {
				return 0, err
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO mail_aliases(id,mail_domain_id,local_part,destinations)
VALUES(CASE WHEN $1=0 THEN nextval('mail_aliases_id_seq') ELSE $1 END,$2,$3,$4)
ON CONFLICT(id) DO UPDATE SET local_part=EXCLUDED.local_part,destinations=EXCLUDED.destinations,updated_at=now()
WHERE mail_aliases.mail_domain_id=EXCLUDED.mail_domain_id RETURNING id`,
			input.ID, input.MailDomainID, input.LocalPart, pq.Array(destinations)).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			err = errors.New("alias does not belong to the subscription")
		}
		return id, err
	})
}

func (s *SQLStore) DeleteMailbox(ctx context.Context, subscriptionID, id int64) error {
	return s.deleteAccountService(ctx, subscriptionID, `DELETE FROM mailboxes mb USING mail_domains md
WHERE mb.id=$1 AND mb.mail_domain_id=md.id AND md.subscription_id=$2`, id)
}

func (s *SQLStore) DeleteMailAlias(ctx context.Context, subscriptionID, id int64) error {
	return s.deleteAccountService(ctx, subscriptionID, `DELETE FROM mail_aliases alias USING mail_domains md
WHERE alias.id=$1 AND alias.mail_domain_id=md.id AND md.subscription_id=$2`, id)
}

func ensureMailDomainBelongsTx(ctx context.Context, tx *sql.Tx, subscriptionID, mailDomainID int64) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mail_domains WHERE id=$1 AND subscription_id=$2 AND NOT delete_requested)`, mailDomainID, subscriptionID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("mail domain does not belong to the subscription")
	}
	return nil
}

// ensureAliasDestinationTx keeps forwarders inside the tenant: a destination
// must be an existing mailbox under a mail domain of the same subscription.
// External forwarding is a documented follow-up.
func ensureAliasDestinationTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, address string) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id
WHERE md.subscription_id=$2 AND lower(mb.local_part)||'@'||md.domain=$1)`, address, subscriptionID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("alias destination %q is not a mailbox of this subscription", address)
	}
	return nil
}

func enforceMailCountTx(ctx context.Context, tx *sql.Tx, table string, subscriptionID int64, limit int) error {
	if limit == -1 {
		return nil
	}
	if limit == 0 {
		return ErrExceeded
	}
	var query string
	switch table {
	case "mailboxes":
		query = `SELECT COUNT(*) FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.subscription_id=$1`
	case "mail_aliases":
		query = `SELECT COUNT(*) FROM mail_aliases alias JOIN mail_domains md ON md.id=alias.mail_domain_id WHERE md.subscription_id=$1`
	default:
		return errors.New("unsupported mail count")
	}
	var count int
	if err := tx.QueryRowContext(ctx, query, subscriptionID).Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return fmt.Errorf("%w: %s %d / %d", ErrExceeded, table, count, limit)
	}
	return nil
}
