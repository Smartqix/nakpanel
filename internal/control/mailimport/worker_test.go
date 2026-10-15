package mailimport

import (
	"context"
	"errors"
	"testing"
	"time"

	transport "github.com/nakroteck/nakpanel/internal/mailimport"
)

func TestCrashBeforeReceipt(t *testing.T) { testImportRecovery(t, false) }
func TestCrashAfterAppend(t *testing.T)   { testImportRecovery(t, true) }
func testImportRecovery(t *testing.T, exists bool) {
	source := &memorySource{messages: []transport.Message{testMessage("one")}}
	target := &memoryTarget{receipts: map[string]transport.Message{}}
	store := newMemoryJobStore()
	store.messages = []MessageRecord{{ID: 1, Message: source.messages[0], State: "appending", Token: "receipt"}}
	if exists {
		target.receipts["receipt"] = source.messages[0]
	}
	engine := Engine{Store: store, Factory: memoryFactory{source, target}}
	_ = engine.Run(context.Background(), "import", 1)
	if target.appends != 0 {
		t.Fatal("uncertain attempt appended again")
	}
	if exists && store.state != "complete" {
		t.Fatalf("verified existing append not completed: %s", store.state)
	}
	if !exists && store.state != "attention_required" {
		t.Fatalf("unknown outcome hidden: %s", store.state)
	}
}
func TestPauseResume(t *testing.T) {
	s := newMemoryJobStore()
	s.valid = false
	target := &memoryTarget{receipts: map[string]transport.Message{}}
	engine := Engine{Store: s, Factory: memoryFactory{&memorySource{messages: []transport.Message{testMessage("one")}}, target}}
	_ = engine.Run(context.Background(), "import", 1)
	if target.appends != 0 {
		t.Fatal("paused import wrote mail")
	}
	s.valid = true
	_ = engine.Run(context.Background(), "import", 1)
	if target.appends != 1 || s.state != "complete" {
		t.Fatalf("resume: %d %s", target.appends, s.state)
	}
}
func TestSourceCatchup(t *testing.T) {
	s := newMemoryJobStore()
	source := &memorySource{messages: []transport.Message{testMessage("one")}, catchup: true}
	target := &memoryTarget{receipts: map[string]transport.Message{}}
	err := (&Engine{Store: s, Factory: memoryFactory{source, target}}).Run(context.Background(), "import", 1)
	if err != nil || target.appends != 2 || s.state != "complete" {
		t.Fatalf("catch-up: %d %s %v", target.appends, s.state, err)
	}
}
func TestQuotaFailure(t *testing.T) {
	s := newMemoryJobStore()
	target := &memoryTarget{receipts: map[string]transport.Message{}, err: errors.New("quota")}
	_ = (&Engine{Store: s, Factory: memoryFactory{&memorySource{messages: []transport.Message{testMessage("one")}}, target}}).Run(context.Background(), "import", 1)
	if s.state == "complete" {
		t.Fatal("quota failure declared complete")
	}
}
func TestUnsupportedFlagWarning(t *testing.T) {
	s := newMemoryJobStore()
	target := &memoryTarget{receipts: map[string]transport.Message{}, err: errors.New("unsupported flags")}
	_ = (&Engine{Store: s, Factory: memoryFactory{&memorySource{messages: []transport.Message{testMessage("one")}}, target}}).Run(context.Background(), "import", 1)
	if s.state != "attention_required" {
		t.Fatalf("unsupported flag hidden: %s", s.state)
	}
}
func TestUnknownReceiptCannotComplete(t *testing.T) { testImportRecovery(t, false) }

func TestImportVerifiesThroughFreshDestinationConnection(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "persistent", true: "session-only"}[missing], func(t *testing.T) {
			store := newMemoryJobStore()
			factory := &reopeningFactory{source: &memorySource{messages: []transport.Message{testMessage("one")}}, target: &memoryTarget{receipts: map[string]transport.Message{}}, missing: missing}
			if err := (&Engine{Store: store, Factory: factory}).Run(context.Background(), "import", 1); err != nil {
				t.Fatal(err)
			}
			want := "complete"
			if missing {
				want = "attention_required"
			}
			if factory.opens < 2 || store.state != want {
				t.Fatalf("fresh-connection check: opens=%d state=%s, want %s", factory.opens, store.state, want)
			}
		})
	}
}

func TestImportRejectsEmptyDiscovery(t *testing.T) {
	store := newMemoryJobStore()
	engine := Engine{Store: store, Factory: memoryFactory{&memorySource{}, &memoryTarget{}}}
	if err := engine.Prepare(context.Background(), "import"); err == nil {
		t.Fatal("empty discovery accepted as an importable source")
	}
}

type reopeningFactory struct {
	source  *memorySource
	target  *memoryTarget
	missing bool
	opens   int
}

func (f *reopeningFactory) Open(context.Context, Job) (Source, Target, error) {
	f.opens++
	if f.opens > 1 && f.missing {
		return f.source, &memoryTarget{receipts: map[string]transport.Message{}}, nil
	}
	return f.source, f.target, nil
}
func testMessage(key string) transport.Message {
	return transport.Message{Identity: transport.MessageIdentity{Folder: "INBOX", UIDValidity: 1, UID: uint32(len(key)), Key: key}, Body: []byte(key), InternalDate: time.Unix(100, 0), Size: int64(len(key))}
}

type memorySource struct {
	messages []transport.Message
	catchup  bool
	scans    int
}

func (s *memorySource) Discover(context.Context) ([]transport.Folder, error) {
	s.scans++
	if s.catchup && s.scans == 2 {
		s.messages = append(s.messages, testMessage("second"))
	}
	return []transport.Folder{{Name: "INBOX", UIDValidity: 1, Messages: s.messages}}, nil
}
func (s *memorySource) Read(_ context.Context, id transport.MessageIdentity) (transport.Message, error) {
	for _, m := range s.messages {
		if m.Identity.String() == id.String() {
			return m, nil
		}
	}
	return transport.Message{}, errors.New("not found")
}
func (*memorySource) Close() error { return nil }

type memoryTarget struct {
	receipts map[string]transport.Message
	appends  int
	err      error
}

func (*memoryTarget) EnsureFolder(context.Context, string) error { return nil }
func (t *memoryTarget) Append(_ context.Context, m transport.Message, token string) (transport.Receipt, error) {
	t.appends++
	if t.err != nil {
		return transport.Receipt{}, t.err
	}
	m.Identity.UID = uint32(len(t.receipts) + 1)
	t.receipts[token] = m
	return transport.Receipt{Folder: m.Identity.Folder, UID: m.Identity.UID, UIDValidity: 1}, nil
}
func (t *memoryTarget) FindReceipt(_ context.Context, folder, token string) ([]transport.Receipt, error) {
	if m, ok := t.receipts[token]; ok {
		return []transport.Receipt{{Folder: folder, UID: m.Identity.UID, UIDValidity: 1}}, nil
	}
	return nil, nil
}
func (t *memoryTarget) Read(_ context.Context, id transport.MessageIdentity) (transport.Message, error) {
	for _, m := range t.receipts {
		if m.Identity.Folder == id.Folder && m.Identity.UID == id.UID {
			return m, nil
		}
	}
	return transport.Message{}, errors.New("missing")
}
func (*memoryTarget) Close() error { return nil }

type memoryFactory struct {
	s *memorySource
	t *memoryTarget
}

func (f memoryFactory) Open(context.Context, Job) (Source, Target, error) { return f.s, f.t, nil }

type memoryJobStore struct {
	messages []MessageRecord
	state    string
	valid    bool
}

func newMemoryJobStore() *memoryJobStore                               { return &memoryJobStore{state: "queued", valid: true} }
func (s *memoryJobStore) Lock(context.Context, string) (func(), error) { return func() {}, nil }
func (s *memoryJobStore) Job(context.Context, string) (Job, error) {
	return Job{ID: "import", Revision: 1}, nil
}
func (s *memoryJobStore) Current(context.Context, string, int64) (bool, error) { return s.valid, nil }
func (s *memoryJobStore) SetState(_ context.Context, _ string, _ int64, state, _ string) error {
	s.state = state
	return nil
}
func (s *memoryJobStore) Discover(_ context.Context, _ string, folders []transport.Folder) error {
	for _, f := range folders {
		for _, m := range f.Messages {
			found := false
			for _, r := range s.messages {
				found = found || r.Message.Identity.String() == m.Identity.String()
			}
			if !found {
				s.messages = append(s.messages, MessageRecord{ID: int64(len(s.messages) + 1), Message: m, State: "pending", Token: m.Identity.Key})
			}
		}
	}
	return nil
}
func (s *memoryJobStore) Messages(context.Context, string) ([]MessageRecord, error) {
	return s.messages, nil
}
func (s *memoryJobStore) Checkpoint(_ context.Context, _ string, record MessageRecord) error {
	for i, m := range s.messages {
		if m.ID == record.ID {
			s.messages[i] = record
			return nil
		}
	}
	return errors.New("missing record")
}
func (*memoryJobStore) Retire(context.Context, string) error { return nil }
