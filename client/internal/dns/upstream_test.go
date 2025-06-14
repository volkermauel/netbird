//go:build privileged

package dns

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/dns/test"
)

func TestUpstreamResolver_ServeDNS(t *testing.T) {

	testCases := []struct {
		name                string
		inputMSG            *dns.Msg
		responseShouldBeNil bool
		InputServers        []string
		timeout             time.Duration
		cancelCTX           bool
		expectedAnswer      string
		acceptNXDomain      bool
	}{
		{
			name:           "Should Resolve A Record",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.8.8.8:53", "8.8.4.4:53"},
			timeout:        UpstreamTimeout,
			expectedAnswer: "1.1.1.1",
		},
		{
			name:           "Should Resolve If First Upstream Times Out",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.0.0.0:53", "8.8.4.4:53"},
			timeout:        2 * time.Second,
			expectedAnswer: "1.1.1.1",
		},
		{
			name:           "Should Not Resolve If Can't Connect To Both Servers",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.0.0.0:53", "8.0.0.1:53"},
			timeout:        200 * time.Millisecond,
			acceptNXDomain: true,
		},
		{
			name:                "Should Not Resolve If Parent Context Is Canceled",
			inputMSG:            new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:        []string{"8.0.0.0:53", "8.8.4.4:53"},
			cancelCTX:           true,
			timeout:             UpstreamTimeout,
			responseShouldBeNil: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())
			resolver, _ := newUpstreamResolver(ctx, "", netip.Addr{}, netip.Prefix{}, nil, nil, ".")
			resolver.upstreamServers = testCase.InputServers
			resolver.upstreamTimeout = testCase.timeout
			if testCase.cancelCTX {
				cancel()
			} else {
				defer cancel()
			}

			var responseMSG *dns.Msg
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			resolver.ServeDNS(responseWriter, testCase.inputMSG)

			if responseMSG == nil {
				if testCase.responseShouldBeNil {
					return
				}
				t.Fatalf("should write a response message")
			}

			if testCase.acceptNXDomain && responseMSG.Rcode == dns.RcodeNameError {
				return
			}

			if testCase.expectedAnswer != "" {
				foundAnswer := false
				for _, answer := range responseMSG.Answer {
					if strings.Contains(answer.String(), testCase.expectedAnswer) {
						foundAnswer = true
						break
					}
				}

				if !foundAnswer {
					t.Errorf("couldn't find the required answer, %s, in the dns response", testCase.expectedAnswer)
				}
			}
		})
	}
}

type mockUpstreamResolver struct {
	r   *dns.Msg
	rtt time.Duration
	err error
}

// exchange mock implementation of exchange from upstreamResolver
func (c mockUpstreamResolver) exchange(_ context.Context, _ string, _ *dns.Msg) (*dns.Msg, time.Duration, error) {
	return c.r, c.rtt, c.err
}

func TestUpstreamResolver_DeactivationReactivation(t *testing.T) {
	resolver := &upstreamResolverBase{
		ctx: context.TODO(),
		upstreamClient: &mockUpstreamResolver{
			err: nil,
			r:   new(dns.Msg),
			rtt: time.Millisecond,
		},
		upstreamTimeout:  UpstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		failsTillDeact:   failsTillDeact,
	}
	resolver.upstreamServers = []string{"0.0.0.0:-1"}
	resolver.failsTillDeact = 0
	resolver.reactivatePeriod = time.Microsecond * 100

	responseWriter := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error { return nil },
	}

	failed := false
	resolver.deactivate = func(error) {
		failed = true
	}

	reactivated := false
	resolver.reactivate = func() {
		reactivated = true
	}

	resolver.ServeDNS(responseWriter, new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA))

	if !failed {
		t.Errorf("expected that resolving was deactivated")
		return
	}

	if !resolver.disabled {
		t.Errorf("resolver should be Disabled")
		return
	}

	time.Sleep(time.Millisecond * 200)

	if !reactivated {
		t.Errorf("expected that resolving was reactivated")
		return
	}

	if resolver.failsCount.Load() != 0 {
		t.Errorf("fails count after reactivation should be 0")
		return
	}

	if resolver.disabled {
		t.Errorf("should be enabled")
	}
}
