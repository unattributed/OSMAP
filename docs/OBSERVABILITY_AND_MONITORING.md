# Observability And Monitoring

## Purpose

This document defines the observability expectations that follow from the Phase
4 architecture. OSMAP is a security-sensitive browser access layer, so
visibility is not optional operational polish.

## Logging Requirements

The system should emit logs that allow operators to investigate:

- authentication successes and failures
- MFA-related events
- session creation, revocation, and unusual proliferation
- high-value user actions such as send attempts and significant account events
- application errors relevant to security or availability
- suspicious backend interaction patterns

Logs should be structured and consistent enough to support incident review
without requiring deep guesswork.

## Metrics

The project should eventually expose basic operational metrics for:

- request volume and error rates
- login success and failure rates
- session counts
- backend dependency health
- submission-related error rates

Metrics should stay narrowly useful. The goal is operator clarity, not a
telemetry empire.

## Alerting Rules

The architecture should support alerting or review thresholds for:

- repeated authentication failures
- suspicious bursts of new sessions
- unusual submission behavior
- persistent backend communication failures
- application crash loops or health-check failures

## Anomaly Detection

At minimum, operators should be able to notice:

- likely credential attacks
- suspicious account takeover patterns
- session behavior that departs from expected use
- message submission behavior that suggests compromise or abuse

## Abuse Monitoring

Observability should support coordination with the existing mail stack so that:

- browser-side auth events can be correlated with submission abuse
- suspicious mail activity is not treated in isolation from account activity
- operators can distinguish likely user mistakes from likely malicious behavior

## Administrative Visibility

The system should give administrators a clear view of:

- current service health
- security-relevant events
- recent auth and session activity
- whether the app is behaving within its expected operational profile

## OpenBSD-Friendly Monitoring Posture

Monitoring should fit a conservative OpenBSD deployment:

- avoid unnecessary heavyweight telemetry dependencies
- prefer simple logs and narrowly scoped metrics
- keep runtime monitoring additions small and supportable
- ensure observability design does not undermine the project's minimal-dependency
  goals
