package azsdk

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/tracing/azotel"
	"github.com/azure/azure-dev/cli/azd/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type ClientOptionsBuilder struct {
	transport        policy.Transporter
	perCallPolicies  []policy.Policy
	perRetryPolicies []policy.Policy
}

func NewClientOptionsBuilder() *ClientOptionsBuilder {
	return &ClientOptionsBuilder{
		perCallPolicies:  []policy.Policy{&spanPolicy{name: "external.http.call"}},
		perRetryPolicies: []policy.Policy{&spanPolicy{name: "external.http.request"}},
	}
}

// Sets the underlying transport used for executing HTTP requests
func (b *ClientOptionsBuilder) WithTransport(transport policy.Transporter) *ClientOptionsBuilder {
	b.transport = transport
	return b
}

// Appends per-call policies into the HTTP pipeline
func (b *ClientOptionsBuilder) WithPerCallPolicy(policy policy.Policy) *ClientOptionsBuilder {
	b.perCallPolicies = append(b.perCallPolicies, policy)
	return b
}

// Appends per-retry policies into the HTTP pipeline
func (b *ClientOptionsBuilder) WithPerRetryPolicy(policy policy.Policy) *ClientOptionsBuilder {
	b.perRetryPolicies = append(b.perRetryPolicies, policy)
	return b
}

// Builds the az core client options for data plane operations
// These options include the underlying transport to be used.
func (b *ClientOptionsBuilder) BuildCoreClientOptions() *azcore.ClientOptions {
	return &azcore.ClientOptions{
		// Supports mocking for unit tests
		Transport: b.transport,
		// Per request policies to inject into HTTP pipeline
		PerCallPolicies: b.perCallPolicies,
		// Per retry policies to inject into HTTP pipeline
		PerRetryPolicies: b.perRetryPolicies,
	}
}

// Builds the ARM module client options for control plane operations
// These options include the underlying transport to be used.
func (b *ClientOptionsBuilder) BuildArmClientOptions() *arm.ClientOptions {
	azotel.NewTracingProvider(nil, nil)

	return &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			// Supports mocking for unit tests
			Transport: b.transport,
			// Per request policies to inject into HTTP pipeline
			PerCallPolicies: b.perCallPolicies,
			// Per retry policies to inject into HTTP pipeline
			PerRetryPolicies: b.perRetryPolicies,
		},
	}
}

type spanPolicy struct {
	name string
}

func (p *spanPolicy) Do(req *policy.Request) (*http.Response, error) {
	ctx, span := telemetry.GetTracer().Start(req.Raw().Context(), p.name, trace.WithAttributes(
		attribute.String("http.method", req.Raw().Method),
		attribute.String("http.url", req.Raw().URL.String()),
		attribute.String("net.peer.name", req.Raw().URL.Hostname()),
	))
	defer span.End()

	res, err := req.Clone(ctx).Next()

	if res != nil {
		span.SetAttributes(
			attribute.Int("http.status_code", res.StatusCode),
		)
	}

	if err != nil || (res.StatusCode >= 400 && res.StatusCode <= 599) {
		span.SetStatus(codes.Error, "")
	}

	return res, err
}
