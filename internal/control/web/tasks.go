package web

import (
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

type TaskItem struct {
	ID          int64      `json:"id"`
	Kind        string     `json:"kind"`
	Label       string     `json:"label"`
	Target      string     `json:"target"`
	State       string     `json:"state"`
	Tone        string     `json:"tone"`
	CreatedAt   time.Time  `json:"created_at"`
	FinalizedAt *time.Time `json:"finalized_at"`
	Error       string     `json:"error"`
}

func TaskItems(jobs []dashboard.Job) []TaskItem {
	items := make([]TaskItem, 0, 8)
	for _, job := range jobs {
		if len(items) == 8 {
			break
		}
		item := TaskItem{ID: job.ID, Kind: job.Kind, Label: humanJobKind(job.Kind), Target: job.Target, State: job.State, Tone: taskTone(job.State), CreatedAt: job.CreatedAt, Error: job.LastError}
		if job.FinalizedAt.Valid {
			finalized := job.FinalizedAt.Time
			item.FinalizedAt = &finalized
		}
		items = append(items, item)
	}
	return items
}

func taskTone(state string) string {
	switch state {
	case "completed":
		return "ok"
	case "discarded", "failed", "cancelled":
		return "fail"
	case "running":
		return "run"
	default:
		return "pend"
	}
}
