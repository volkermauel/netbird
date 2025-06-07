package traffic

import (
	"testing"

	api "github.com/netbirdio/netbird/management/server/http/api"
)

func TestAggregateByUser(t *testing.T) {
	events := []api.NetworkTrafficEvent{
		{
			User:      api.NetworkTrafficUser{Id: "u1", Email: "a@example.com"},
			RxBytes:   100,
			TxBytes:   50,
			RxPackets: 10,
			TxPackets: 5,
		},
		{
			User:      api.NetworkTrafficUser{Id: "u1", Email: "a@example.com"},
			RxBytes:   200,
			TxBytes:   100,
			RxPackets: 20,
			TxPackets: 10,
		},
		{
			User:      api.NetworkTrafficUser{Id: "u2", Email: "b@example.com"},
			RxBytes:   300,
			TxBytes:   150,
			RxPackets: 30,
			TxPackets: 15,
		},
	}

	got := AggregateByUser(events)

	if len(got) != 2 {
		t.Fatalf("expected 2 users, got %d", len(got))
	}

	u1 := got["u1"]
	if u1 == nil || u1.RxBytes != 300 || u1.TxBytes != 150 || u1.RxPackets != 30 || u1.TxPackets != 15 {
		t.Errorf("unexpected stats for u1: %+v", u1)
	}

	u2 := got["u2"]
	if u2 == nil || u2.RxBytes != 300 || u2.TxBytes != 150 || u2.RxPackets != 30 || u2.TxPackets != 15 {
		t.Errorf("unexpected stats for u2: %+v", u2)
	}
}
