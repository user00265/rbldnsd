// Copyright (c) 2024 Elisamuel Resto Donate <sam@samresto.dev>
// SPDX-License-Identifier: MIT

// Package metrics implements OpenTelemetry and Prometheus metrics collection.
// It tracks query counts, response times, and error rates per zone.
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Metrics manages OpenTelemetry and Prometheus metric collection.
type Metrics struct {
	queryCounter     metric.Int64Counter
	responseCounter  metric.Int64Counter
	errorCounter     metric.Int64Counter
	latencyRecorder  metric.Float64Histogram
	prometheusAddr   string
	prometheusServer *http.Server
}

// New initializes metrics with OpenTelemetry and/or Prometheus endpoints.
func New(otelEndpoint string, prometheusEndpoint string) (*Metrics, error) {
	m := &Metrics{
		prometheusAddr: prometheusEndpoint,
	}

	// Metrics are enabled if at least one endpoint is provided
	if otelEndpoint == "" && prometheusEndpoint == "" {
		return m, nil
	}

	ctx := context.Background()

	var readers []sdkmetric.Reader

	// Set up OTLP HTTP exporter if endpoint provided
	if otelEndpoint != "" {
		exporter, err := otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpoint(otelEndpoint),
			otlpmetrichttp.WithInsecure(),
		)
		if err != nil {
			slog.Warn("failed to create OTLP exporter", "error", err)
		} else {
			readers = append(readers, sdkmetric.NewPeriodicReader(exporter))
			slog.Info("OTLP exporter configured", "endpoint", otelEndpoint)
		}
	}

	// Set up Prometheus exporter if endpoint provided
	if prometheusEndpoint != "" {
		promExporter, err := prometheus.New()
		if err != nil {
			slog.Warn("failed to create Prometheus exporter", "error", err)
		} else {
			readers = append(readers, promExporter)
			slog.Info("Prometheus exporter configured", "endpoint", prometheusEndpoint)
		}
	}

	// Build meter provider with all readers
	if len(readers) == 0 {
		slog.Warn("no metric exporters configured")
		return m, nil
	}

	var opts []sdkmetric.Option
	for _, reader := range readers {
		opts = append(opts, sdkmetric.WithReader(reader))
	}
	meterProvider := sdkmetric.NewMeterProvider(opts...)
	otel.SetMeterProvider(meterProvider)

	meter := otel.Meter("rbldnsd")

	// Create instruments
	queryCounter, err := meter.Int64Counter(
		"rbldnsd.queries.total",
		metric.WithDescription("Total DNS queries"),
	)
	if err != nil {
		slog.Warn("failed to create query counter", "error", err)
		return m, nil
	}

	responseCounter, err := meter.Int64Counter(
		"rbldnsd.responses.total",
		metric.WithDescription("Total DNS responses"),
	)
	if err != nil {
		slog.Warn("failed to create response counter", "error", err)
		return m, nil
	}

	errorCounter, err := meter.Int64Counter(
		"rbldnsd.errors.total",
		metric.WithDescription("Total errors"),
	)
	if err != nil {
		slog.Warn("failed to create error counter", "error", err)
		return m, nil
	}

	latencyRecorder, err := meter.Float64Histogram(
		"rbldnsd.query.latency_ms",
		metric.WithDescription("Query latency in milliseconds"),
	)
	if err != nil {
		slog.Warn("failed to create latency recorder", "error", err)
		return m, nil
	}

	m.queryCounter = queryCounter
	m.responseCounter = responseCounter
	m.errorCounter = errorCounter
	m.latencyRecorder = latencyRecorder

	// Start Prometheus HTTP server if configured
	if m.prometheusAddr != "" {
		if err := m.startPrometheusServer(); err != nil {
			slog.Warn("failed to start Prometheus server", "error", err)
		}
	}

	return m, nil
}

// RecordQuery records a DNS query
func (m *Metrics) RecordQuery(zone string, qtype string) {
	if m.queryCounter == nil {
		return
	}

	m.queryCounter.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("zone", zone),
			attribute.String("qtype", qtype),
		),
	)
}

// RecordResponse records a DNS response
func (m *Metrics) RecordResponse(zone string, found bool) {
	if m.responseCounter == nil {
		return
	}

	m.responseCounter.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("zone", zone),
			attribute.Bool("found", found),
		),
	)
}

// RecordError records an error
func (m *Metrics) RecordError(zone string, errType string) {
	if m.errorCounter == nil {
		return
	}

	m.errorCounter.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("zone", zone),
			attribute.String("type", errType),
		),
	)
}

// RecordLatency records query latency in milliseconds
func (m *Metrics) RecordLatency(zone string, latencyMs float64) {
	if m.latencyRecorder == nil {
		return
	}

	m.latencyRecorder.Record(context.Background(), latencyMs,
		metric.WithAttributes(
			attribute.String("zone", zone),
		),
	)
}

// startPrometheusServer starts the HTTP server for Prometheus metrics
func (m *Metrics) startPrometheusServer() error {
	// Create a new ServeMux to avoid conflicts with default http.DefaultServeMux
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	addr := m.prometheusAddr
	m.prometheusServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		slog.Info("Starting Prometheus metrics server", "endpoint", addr+"/metrics")
		if err := m.prometheusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Prometheus metrics server error", "error", err)
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the Prometheus metrics server
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.prometheusServer != nil {
		return m.prometheusServer.Shutdown(ctx)
	}
	return nil
}

// StartPrometheus starts a Prometheus metrics endpoint
// DEPRECATED: Use New() with prometheusEndpoint parameter instead
func StartPrometheus(port int) error {
	// Create Prometheus exporter
	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	// Get the current meter provider and add Prometheus reader to it
	// Note: This must be called before metrics.New() to work properly
	currentProvider := otel.GetMeterProvider()
	if _, ok := currentProvider.(*sdkmetric.MeterProvider); ok {
		// Provider already exists, need to create a new one with both readers
		slog.Warn("MeterProvider already set. Prometheus may not receive all metrics.")
	}

	// Create a new meter provider with Prometheus reader
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(provider)

	// Set up HTTP handler for Prometheus metrics using a dedicated mux
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	// Start HTTP server in a goroutine
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	go func() {
		slog.Info("Starting Prometheus metrics server", "endpoint", addr+"/metrics")
		if err := http.ListenAndServe(addr, mux); err != nil {
			slog.Error("Prometheus metrics server error", "error", err)
		}
	}()

	return nil
}
