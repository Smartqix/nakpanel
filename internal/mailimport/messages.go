package mailimport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const MaxMessageBytes = 64 << 20

var (
	ErrSourceChanged = errors.New("mail source changed; review and rediscover before resuming")
	ErrUncertain     = errors.New("message acknowledgement is uncertain; reconcile before retrying")
)

type MessageIdentity struct {
	Folder           string
	UIDValidity, UID uint32
	Key              string
}

func (i MessageIdentity) String() string {
	return fmt.Sprintf("%s/%d/%d/%s", i.Folder, i.UIDValidity, i.UID, i.Key)
}

type Message struct {
	Identity     MessageIdentity
	Body         []byte
	Flags        []string
	InternalDate time.Time
	Size         int64
}
type Folder struct {
	Name        string
	Delimiter   string
	SpecialUse  string
	UIDValidity uint32
	Messages    []Message
}
type Receipt struct {
	Folder           string
	UID, UIDValidity uint32
}

func ReceiptToken(importID, identity string) string {
	v := sha256.Sum256([]byte(importID + "\x00" + identity))
	return "npimport_" + hex.EncodeToString(v[:])
}
func ContentHash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
