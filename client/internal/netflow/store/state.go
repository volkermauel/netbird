package store

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const flowEventsStateName = "netflow_events"

// flowEventsState represents persisted flow events in the state manager.
type flowEventsState struct {
	Events map[uuid.UUID]*types.Event `json:"events"`
}

func (s *flowEventsState) Name() string { return flowEventsStateName }

type StateStore struct {
	mux   sync.Mutex
	mgr   *statemanager.Manager
	state *flowEventsState
}

// NewStateStore creates a new store backed by the state manager.
func NewStateStore(mgr *statemanager.Manager) (*StateStore, error) {
	if mgr == nil {
		return nil, fmt.Errorf("nil state manager")
	}

	st := &flowEventsState{}
	mgr.RegisterState(st)
	if err := mgr.LoadState(st); err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	loaded := mgr.GetState(st)
	if loaded != nil {
		if loadedState, ok := loaded.(*flowEventsState); ok {
			st = loadedState
		}
	}
	if st.Events == nil {
		st.Events = make(map[uuid.UUID]*types.Event)
	}

	return &StateStore{mgr: mgr, state: st}, nil
}

func (s *StateStore) StoreEvent(event *types.Event) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.state.Events[event.ID] = event
	if err := s.mgr.UpdateState(s.state); err != nil {
		log.Warnf("failed to persist flow event state: %v", err)
	}
}

func (s *StateStore) GetEvents() []*types.Event {
	s.mux.Lock()
	defer s.mux.Unlock()

	events := make([]*types.Event, 0, len(s.state.Events))
	for _, e := range s.state.Events {
		events = append(events, e)
	}
	return events
}

func (s *StateStore) DeleteEvents(ids []uuid.UUID) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, id := range ids {
		delete(s.state.Events, id)
	}

	if err := s.mgr.UpdateState(s.state); err != nil {
		log.Warnf("failed to persist flow event state: %v", err)
	}
}

func (s *StateStore) Close() {
	// nothing to do
}
