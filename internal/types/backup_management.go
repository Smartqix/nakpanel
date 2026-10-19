package types

import "time"

type BackupRemovalItem struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
	Retained  bool      `json:"retained"`
}

type BackupRemovalPreview struct {
	SubscriptionID int64               `json:"subscription_id"`
	CustomerID     int64               `json:"customer_id"`
	Items          []BackupRemovalItem `json:"items"`
	SizeBytes      int64               `json:"size_bytes"`
	Digest         string              `json:"digest"`
}
