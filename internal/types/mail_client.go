package types

import "time"

// MailClientProfile contains public connection information, never credentials.
type MailClientProfile struct {
	Hostname     string
	IMAPTLS      bool
	SMTPTLS      bool
	SMTPSTARTTLS bool
	CheckedAt    time.Time
}
