package ops

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"slices"
	"strings"
)

type dnsAppliedRevision struct {
	SiteID         int64    `json:"site_id"`
	SubscriptionID int64    `json:"subscription_id"`
	ZoneID         int64    `json:"zone_id"`
	Revision       int64    `json:"revision"`
	Digest         [32]byte `json:"digest"`
}

func dnsRevisionForRequest(req types.ConfigureDNSZoneReq) (dnsAppliedRevision, error) {
	req.Records = slices.Clone(req.Records)
	slices.SortFunc(req.Records, func(a, b types.DNSRecord) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return strings.Compare(string(left), string(right))
	})
	data, err := json.Marshal(req)
	if err != nil {
		return dnsAppliedRevision{}, err
	}
	return dnsAppliedRevision{SiteID: req.SiteID, SubscriptionID: req.SubscriptionID, ZoneID: req.ZoneID, Revision: req.DesiredRevision, Digest: sha256.Sum256(data)}, nil
}

func checkDNSAppliedRevision(path string, want dnsAppliedRevision) error {
	var previous dnsAppliedRevision
	err := readIdentityFile(path, &previous)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if previous.SiteID != want.SiteID || previous.SubscriptionID != want.SubscriptionID || previous.ZoneID != want.ZoneID || want.Revision < previous.Revision {
		return errors.New("DNS snapshot is stale or belongs to a previous website")
	}
	if want.Revision == previous.Revision && want.Digest != previous.Digest {
		return errors.New("DNS intent changed without advancing its revision")
	}
	return nil
}
