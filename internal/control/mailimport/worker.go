package mailimport

import (
	"context"
	"errors"
	"strings"

	transport "github.com/nakroteck/nakpanel/internal/mailimport"
	"github.com/riverqueue/river"
)

type Job struct {
	ID, State                                                                                     string
	MailboxID, SubscriptionID, Revision                                                           int64
	Address                                                                                       string
	SourceKind, SourceHost, SourceUser, StagingID, ManifestSHA256, SourceSecretID, TargetSecretID string
}
type MessageRecord struct {
	ID                        int64
	Message                   transport.Message
	State, Token, Hash, Error string
	Receipt                   transport.Receipt
}
type Source interface {
	Discover(context.Context) ([]transport.Folder, error)
	Read(context.Context, transport.MessageIdentity) (transport.Message, error)
	Close() error
}
type Target interface {
	EnsureFolder(context.Context, string) error
	Append(context.Context, transport.Message, string) (transport.Receipt, error)
	FindReceipt(context.Context, string, string) ([]transport.Receipt, error)
	Read(context.Context, transport.MessageIdentity) (transport.Message, error)
	Close() error
}
type Factory interface {
	Open(context.Context, Job) (Source, Target, error)
}
type WorkStore interface {
	Lock(context.Context, string) (func(), error)
	Job(context.Context, string) (Job, error)
	Current(context.Context, string, int64) (bool, error)
	SetState(context.Context, string, int64, string, string) error
	Discover(context.Context, string, []transport.Folder) error
	Messages(context.Context, string) ([]MessageRecord, error)
	Checkpoint(context.Context, string, MessageRecord) error
	Retire(context.Context, string) error
}
type Engine struct {
	Store   WorkStore
	Factory Factory
}

func (e *Engine) Prepare(ctx context.Context, id string) error {
	job, err := e.Store.Job(ctx, id)
	if err != nil {
		return err
	}
	source, target, err := e.Factory.Open(ctx, job)
	if err != nil {
		return errors.New("mail connection failed; check source and destination credentials and TLS")
	}
	defer source.Close()
	defer target.Close()
	folders, err := source.Discover(ctx)
	if err != nil {
		return errors.New("source discovery failed; check the source layout, limits and permissions")
	}
	var messageCount int
	for _, folder := range folders {
		messageCount += len(folder.Messages)
	}
	if messageCount == 0 {
		return errors.New("no source messages were found; verify the account and folder visibility before importing")
	}
	if capacity, ok := target.(interface {
		AvailableBytes(context.Context) (int64, error)
	}); ok {
		remaining, err := capacity.AvailableBytes(ctx)
		if err != nil {
			return err
		}
		var required int64
		for _, folder := range folders {
			for _, msg := range folder.Messages {
				required += msg.Size
			}
		}
		if remaining >= 0 && required > remaining {
			return errors.New("source messages exceed the destination mailbox's remaining quota")
		}
	}
	if err = e.Store.Discover(ctx, id, folders); err != nil {
		return err
	}
	if store, ok := e.Store.(interface {
		Prepared(context.Context, string) error
	}); ok {
		return store.Prepared(ctx, id)
	}
	return nil
}
func (e *Engine) Cleanup(ctx context.Context, id string) error {
	job, err := e.Store.Job(ctx, id)
	if err != nil {
		return err
	}
	if cleaner, ok := e.Factory.(interface {
		Cleanup(context.Context, Job) error
	}); ok {
		return cleaner.Cleanup(ctx, job)
	}
	return nil
}

var ErrSuperseded = errors.New("mail import is paused, cancelled or superseded")

func (e *Engine) Run(ctx context.Context, id string, revision int64) error {
	unlock, err := e.Store.Lock(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	job, err := e.Store.Job(ctx, id)
	if err != nil {
		return err
	}
	// Terminal retries finish disposal without reopening retired credentials.
	if job.State == "complete" || job.State == "cancelled" {
		if err = e.Store.Retire(ctx, id); err != nil {
			return err
		}
		return e.Cleanup(ctx, id)
	}
	current, err := e.Store.Current(ctx, id, revision)
	if err != nil {
		return err
	}
	if !current {
		return nil
	}
	source, target, err := e.Factory.Open(ctx, job)
	if err != nil {
		_ = e.Store.SetState(ctx, id, revision, "attention_required", "Mail connection or authentication failed. Verify credentials and retry.")
		return nil
	}
	defer source.Close()
	defer target.Close()
	for scan := 0; scan < 2; scan++ {
		if err = e.active(ctx, id, revision); err != nil {
			return nil
		}
		if err = e.Store.SetState(ctx, id, revision, "discovering", ""); err != nil {
			return err
		}
		folders, err := source.Discover(ctx)
		if err != nil {
			return e.attention(ctx, id, revision, "Source discovery failed or changed. No source mail was removed.")
		}
		if err = e.Store.Discover(ctx, id, folders); err != nil {
			return e.attention(ctx, id, revision, "Source identity changed. Review the import before resuming.")
		}
		targets := map[string]string{}
		for _, folder := range folders {
			targets[folder.Name] = folder.Name
		}
		if store, ok := e.Store.(interface {
			FolderTargets(context.Context, string) (map[string]string, error)
		}); ok {
			targets, err = store.FolderTargets(ctx, id)
			if err != nil {
				return err
			}
		}
		for _, folder := range folders {
			targetName, included := targets[folder.Name]
			if !included {
				continue
			}
			if scoped, ok := target.(interface {
				EnsureFolderWithRole(context.Context, string, string) error
			}); ok && folder.SpecialUse != "" {
				err = scoped.EnsureFolderWithRole(ctx, targetName, folder.SpecialUse)
			} else {
				err = target.EnsureFolder(ctx, targetName)
			}
			if err != nil {
				return e.attention(ctx, id, revision, "A destination folder could not be prepared.")
			}
		}
		records, err := e.Store.Messages(ctx, id)
		if err != nil {
			return err
		}
		if err = e.Store.SetState(ctx, id, revision, "copying", ""); err != nil {
			return err
		}
		for _, record := range records {
			if err = e.active(ctx, id, revision); err != nil {
				return nil
			}
			if record.State == "verified" || record.State == "excluded" {
				continue
			}
			msg, err := source.Read(ctx, record.Message.Identity)
			if err != nil {
				return e.attention(ctx, id, revision, "A source message cannot be read. Nothing has been deleted.")
			}
			hash := transport.ContentHash(msg.Body)
			if record.Hash != "" && record.Hash != hash {
				return e.attention(ctx, id, revision, "Source message content changed; import needs review.")
			}
			record.Hash = hash
			if record.State == "pending" || record.State == "failed" {
				record.Message = msg
			} else {
				// A recovered receipt belongs to the metadata of the original append.
				msg.Flags = record.Message.Flags
				msg.InternalDate = record.Message.InternalDate
				msg.Size = record.Message.Size
			}
			targetName, included := targets[msg.Identity.Folder]
			if !included {
				continue
			}
			copyMessage := msg
			copyMessage.Identity.Folder = targetName
			if record.State == "appending" || record.State == "uncertain" {
				receipts, err := target.FindReceipt(ctx, targetName, record.Token)
				if err != nil || len(receipts) != 1 {
					record.State = "uncertain"
					record.Error = "The previous append cannot be proven. Do not retry this message blindly."
					_ = e.Store.Checkpoint(ctx, id, record)
					return e.attention(ctx, id, revision, record.Error)
				}
				record.Receipt = receipts[0]
				record.State = "copied"
			}
			if record.State == "pending" || record.State == "failed" {
				record.State = "appending"
				if err = e.Store.Checkpoint(ctx, id, record); err != nil {
					return err
				}
				if err = e.active(ctx, id, revision); err != nil {
					return nil
				}
				record.Receipt, err = target.Append(ctx, copyMessage, record.Token)
				if err != nil {
					record.State = "failed"
					record.Error = "Destination rejected this message. Check quota and supported flags before resuming."
					if errors.Is(err, transport.ErrUncertain) {
						record.State = "uncertain"
						record.Error = "The append acknowledgement was lost. Reconcile the receipt before retrying."
					}
					_ = e.Store.Checkpoint(ctx, id, record)
					return e.attention(ctx, id, revision, record.Error)
				}
				record.State = "copied"
				if err = e.Store.Checkpoint(ctx, id, record); err != nil {
					return err
				}
			}
			if err = e.Store.SetState(ctx, id, revision, "verifying", ""); err != nil {
				return err
			}
			got, err := target.Read(ctx, transport.MessageIdentity{Folder: record.Receipt.Folder, UID: record.Receipt.UID, UIDValidity: record.Receipt.UIDValidity})
			if err != nil || !sameMessage(msg, got, record.Token) {
				record.Error = "Copied message content, date or flags could not be verified."
				_ = e.Store.Checkpoint(ctx, id, record)
				return e.attention(ctx, id, revision, record.Error)
			}
			record.State = "verified"
			record.Error = ""
			if err = e.Store.Checkpoint(ctx, id, record); err != nil {
				return err
			}
		}
	}
	if err = e.active(ctx, id, revision); err != nil {
		return nil
	}
	if err = e.verifyFreshConnection(ctx, job); err != nil {
		return e.attention(ctx, id, revision, "Destination verification failed on a fresh connection. The copied mail is retained; review folder visibility before resuming.")
	}
	if err = e.Store.SetState(ctx, id, revision, "complete", ""); err != nil {
		return err
	}
	if err = e.Store.Retire(ctx, id); err != nil {
		return err
	}
	return e.Cleanup(ctx, id)
}

func (e *Engine) verifyFreshConnection(ctx context.Context, job Job) error {
	source, target, err := e.Factory.Open(ctx, job)
	if err != nil {
		return err
	}
	defer source.Close()
	defer target.Close()
	records, err := e.Store.Messages(ctx, job.ID)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("no messages were discovered")
	}
	for _, record := range records {
		if record.State == "excluded" {
			continue
		}
		if err = e.active(ctx, job.ID, job.Revision); err != nil {
			return err
		}
		if record.State != "verified" || record.Hash == "" {
			return errors.New("message has no verified receipt")
		}
		receipts, err := target.FindReceipt(ctx, record.Receipt.Folder, record.Token)
		if err != nil || len(receipts) != 1 || receipts[0] != record.Receipt {
			return errors.New("destination receipt is not visible")
		}
		got, err := target.Read(ctx, transport.MessageIdentity{Folder: record.Receipt.Folder, UID: record.Receipt.UID, UIDValidity: record.Receipt.UIDValidity})
		if err != nil || transport.ContentHash(got.Body) != record.Hash || !sameMetadata(record.Message, got, record.Token) {
			return errors.New("destination message changed")
		}
	}
	return nil
}
func (e *Engine) active(ctx context.Context, id string, revision int64) error {
	ok, err := e.Store.Current(ctx, id, revision)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSuperseded
	}
	return ctx.Err()
}
func (e *Engine) attention(ctx context.Context, id string, revision int64, message string) error {
	return e.Store.SetState(ctx, id, revision, "attention_required", message)
}
func sameMessage(want, got transport.Message, receipt string) bool {
	return transport.ContentHash(want.Body) == transport.ContentHash(got.Body) && sameMetadata(want, got, receipt)
}
func sameMetadata(want, got transport.Message, receipt string) bool {
	if want.InternalDate.Unix() != got.InternalDate.Unix() {
		return false
	}
	normalize := func(flags []string, ignoredReceipt string) map[string]bool {
		out := map[string]bool{}
		for _, flag := range flags {
			flag = strings.ToLower(flag)
			if flag != `\recent` && (ignoredReceipt == "" || flag != strings.ToLower(ignoredReceipt)) {
				out[flag] = true
			}
		}
		return out
	}
	wantFlags, gotFlags := normalize(want.Flags, ""), normalize(got.Flags, receipt)
	if len(wantFlags) != len(gotFlags) {
		return false
	}
	for flag := range wantFlags {
		if !gotFlags[flag] {
			return false
		}
	}
	return true
}

type ImportWorker struct {
	river.WorkerDefaults[ImportArgs]
	Engine *Engine
}

func (w *ImportWorker) Work(ctx context.Context, job *river.Job[ImportArgs]) error {
	return w.Engine.Run(ctx, job.Args.ImportID, job.Args.Revision)
}
