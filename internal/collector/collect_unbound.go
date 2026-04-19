package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/kahoon/netmon/internal/events"
	"github.com/kahoon/netmon/internal/model"
	"github.com/miekg/dns"
)

const (
	localUnbound     = "127.0.0.1"
	localUnboundPort = "5335"
	dnssecPositive   = "internetsociety.org."
	dnssecNegative   = "dnssec-failed.org."
)

type UnboundCollector struct {
	ProbeTimeout time.Duration
}

func (c UnboundCollector) Collect(ctx context.Context) model.UnboundState {
	positive := c.queryDNSSECPositive(ctx)
	negative := c.queryDNSSECNegative(ctx)
	emitDNSSECTrace(ctx, "dnssec_positive", positive)
	emitDNSSECTrace(ctx, "dnssec_negative", negative)

	return model.UnboundState{
		DNSSEC: model.DNSSECProbeResult{
			Positive: positive,
			Negative: negative,
		},
	}
}

func (c UnboundCollector) queryDNSSECPositive(ctx context.Context) model.DNSSECProbeAttempt {
	msg := new(dns.Msg)
	msg.SetQuestion(dnssecPositive, dns.TypeA)
	msg.RecursionDesired = true
	msg.SetEdns0(1232, true)

	answer, latency, err := dnsExchange(ctx, c.ProbeTimeout, "udp4", localUnbound, localUnboundPort, msg)
	if err != nil {
		return model.DNSSECProbeAttempt{
			Name:    dnssecPositive,
			Target:  net.JoinHostPort(localUnbound, localUnboundPort),
			Status:  classifyDNSSECError(err),
			Latency: latency,
			Detail:  err.Error(),
		}
	}

	attempt := model.DNSSECProbeAttempt{
		Name:    dnssecPositive,
		Target:  net.JoinHostPort(localUnbound, localUnboundPort),
		Latency: latency,
	}
	attempt.Status, attempt.Rcode, attempt.AD, attempt.Detail = validateDNSSECPositiveAnswer(answer)
	return attempt
}

func (c UnboundCollector) queryDNSSECNegative(ctx context.Context) model.DNSSECProbeAttempt {
	msg := new(dns.Msg)
	msg.SetQuestion(dnssecNegative, dns.TypeA)
	msg.RecursionDesired = true
	msg.SetEdns0(1232, true)

	answer, latency, err := dnsExchange(ctx, c.ProbeTimeout, "udp4", localUnbound, localUnboundPort, msg)
	if err != nil {
		return model.DNSSECProbeAttempt{
			Name:    dnssecNegative,
			Target:  net.JoinHostPort(localUnbound, localUnboundPort),
			Status:  classifyDNSSECError(err),
			Latency: latency,
			Detail:  err.Error(),
		}
	}

	attempt := model.DNSSECProbeAttempt{
		Name:    dnssecNegative,
		Target:  net.JoinHostPort(localUnbound, localUnboundPort),
		Latency: latency,
	}
	attempt.Status, attempt.Rcode, attempt.AD, attempt.Detail = validateDNSSECNegativeAnswer(answer)
	return attempt
}

func validateDNSSECPositiveAnswer(answer *dns.Msg) (model.DNSSECProbeStatus, string, bool, string) {
	if answer == nil {
		return model.DNSSECProbeStatusUnexpectedFailure, "", false, "nil response"
	}
	rcode := dns.RcodeToString[answer.Rcode]
	if !answer.Response {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "response missing QR bit"
	}
	if answer.Rcode != dns.RcodeSuccess {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, fmt.Sprintf("expected NOERROR, got %s", rcode)
	}
	if len(answer.Answer) == 0 {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "no A answers"
	}
	if !answer.AuthenticatedData {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, false, "missing AD bit"
	}
	for _, rr := range answer.Answer {
		if _, ok := rr.(*dns.A); ok {
			return model.DNSSECProbeStatusOK, rcode, true, ""
		}
	}
	return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "no A answers"
}

func validateDNSSECNegativeAnswer(answer *dns.Msg) (model.DNSSECProbeStatus, string, bool, string) {
	if answer == nil {
		return model.DNSSECProbeStatusUnexpectedFailure, "", false, "nil response"
	}
	rcode := dns.RcodeToString[answer.Rcode]
	if !answer.Response {
		return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, "response missing QR bit"
	}
	if answer.Rcode == dns.RcodeServerFailure {
		return model.DNSSECProbeStatusOK, rcode, answer.AuthenticatedData, ""
	}
	if answer.Rcode == dns.RcodeSuccess {
		return model.DNSSECProbeStatusUnexpectedSuccess, rcode, answer.AuthenticatedData, "expected SERVFAIL, got NOERROR"
	}
	return model.DNSSECProbeStatusUnexpectedFailure, rcode, answer.AuthenticatedData, fmt.Sprintf("expected SERVFAIL, got %s", rcode)
}

func classifyDNSSECError(err error) model.DNSSECProbeStatus {
	if err == nil {
		return model.DNSSECProbeStatusOK
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.DNSSECProbeStatusTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.DNSSECProbeStatusTimeout
	}
	return model.DNSSECProbeStatusNetworkError
}

func emitDNSSECTrace(ctx context.Context, kind string, attempt model.DNSSECProbeAttempt) {
	events.Emit(ctx, events.ProbeResult{
		At:       time.Now().Local(),
		Kind:     kind,
		Family:   "local",
		Target:   attempt.Target,
		Status:   attempt.Status.String(),
		Latency:  attempt.Latency,
		Detail:   attempt.Detail,
		Provider: "unbound",
		Rcode:    attempt.Rcode,
		AD:       attempt.AD,
	})
}
