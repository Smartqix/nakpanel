package mailimport

import (
	"context"
	"errors"
	"strings"

	transport "github.com/nakroteck/nakpanel/internal/mailimport"
	"github.com/riverqueue/river"
)

type Job struct {
	ID                                                                                            string
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
	current, err := e.Store.Current(ctx, id, revision)
	if err != nil {
		return err
	}
	if !current {
		return nil
	}
	job, err := e.Store.Job(ctx, id)
	if err != nil {
		return err
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
			record.Message = msg
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
			if err != nil || !sameMessage(msg, got) {
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
	if err = e.Store.SetState(ctx, id, revision, "complete", ""); err != nil {
		return err
	}
	if err = e.Store.Retire(ctx, id); err != nil {
		return err
	}
	return e.Cleanup(ctx, id)
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
func sameMessage(want, got transport.Message) bool {
	if transport.ContentHash(want.Body) != transport.ContentHash(got.Body) || want.InternalDate.Unix() != got.InternalDate.Unix() {
		return false
	}
	flags := map[string]bool{}
	for _, f := range got.Flags {
		flags[strings.ToLower(f)] = true
	}
	for _, f := range want.Flags {
		if !flags[strings.ToLower(f)] {
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
