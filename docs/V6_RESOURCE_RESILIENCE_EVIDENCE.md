# V6 Resource Resilience Evidence

## Claim

V6 must show that bounded expensive-route failures do not make the cheap health
surface unavailable, failure responses remain deterministic, backend timeouts
are bounded, malformed input fails closed, failure output is redacted, and the
service recovers.

## Validator

Run:

```sh
sh maint/live/osmap-live-validate-v6-resource-resilience.ksh
```

The default report is:

```text
maint/live/latest-host-v6-resource-resilience-report.txt
```

The validator requires:

- a passed V6 production-readiness report
- the sanitized V3 live resource-control report
- the sanitized V3 helper-timeout evidence
- successful health probes before and after validation
- current-checkout `http_runtime`, `throttle`, budget-exhaustion, malformed
  framing, oversized-input, and helper-timeout regressions
- a redaction scan over transient command output

The required final markers are:

```text
result=v6_resource_resilience_passed
health_under_pressure=passed
budget_or_timeout_boundary=passed
malformed_request_boundary=passed
recovery=passed
redaction=passed
```

## Production Pressure Disposition

The known mail host is multi-purpose. The default
`production_pressure_not_safe` mode does not manufacture expensive-route load
against it. The report instead binds current health and recovery to current
regression evidence and the earlier sanitized live resource evidence. Use
`isolated_live_observed` only on a target where deliberate saturation is safe.

## Diagnostic Mode

`--dry-run` checks basic execution context and writes a diagnostic-only report.
It cannot contain passed closeout markers and cannot satisfy `make v6-check`.
