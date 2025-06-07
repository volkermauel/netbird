package traffic

import api "github.com/netbirdio/netbird/management/server/http/api"

// UserSummary holds aggregated traffic data per user.
type UserSummary struct {
	UserID    string
	Email     string
	RxBytes   int
	TxBytes   int
	RxPackets int
	TxPackets int
}

// AggregateByUser calculates aggregated traffic statistics from a slice of
// NetworkTrafficEvent. The returned map is keyed by user ID.
func AggregateByUser(events []api.NetworkTrafficEvent) map[string]*UserSummary {
	summary := make(map[string]*UserSummary)
	for _, e := range events {
		id := e.User.Id
		if id == "" {
			id = "unknown"
		}
		s, ok := summary[id]
		if !ok {
			s = &UserSummary{UserID: id, Email: e.User.Email}
			summary[id] = s
		}
		s.RxBytes += e.RxBytes
		s.TxBytes += e.TxBytes
		s.RxPackets += e.RxPackets
		s.TxPackets += e.TxPackets
	}
	return summary
}
