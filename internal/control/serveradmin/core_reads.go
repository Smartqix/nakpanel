package serveradmin

import (
	"context"
	"errors"

	"github.com/nakroteck/nakpanel/internal/types"
)

type coreReadAgent interface {
	ReadJournal(context.Context, types.ReadJournalReq) (types.ReadJournalResult, error)
	InspectUpdates(context.Context) (types.UpdateState, error)
}

// ReadJournal keeps the panel surface read-only and delegates registry and
// output-bound enforcement to the trusted agent.
func (m *Manager) ReadJournal(ctx context.Context, req types.ReadJournalReq) (types.ReadJournalResult, error) {
	agent, ok := m.coreReadAgent()
	if !ok {
		return types.ReadJournalResult{}, errors.New("server journal access is not configured")
	}
	return agent.ReadJournal(ctx, req)
}

func (m *Manager) coreReadAgent() (coreReadAgent, bool) {
	if m == nil || m.agent == nil {
		return nil, false
	}
	agent, ok := m.agent.(coreReadAgent)
	return agent, ok
}
