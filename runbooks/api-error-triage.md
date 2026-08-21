---
name: Which APIs are throwing errors, and what are the errors
surfaces: [metrics, logs]
functions: [api_error_rates, api_error_ratio, api_error_codes, api_error_routes, api_error_callers, error_request_ids, logs_for_request_id, pod_status, recent_events]
keywords: ["which api is failing", "5xx", "500", "502", "503", "504", "errors", "what errors", "error triage", "request id", "trace", "exception", "stack trace", "api errors", "which service is throwing errors", "correlate logs"]
owner: infra
reviewed_on: 2026-08-19
---

Answer this class of question by FOLLOWING THE CHAIN, not by stopping at the first
step. "Service X is throwing 5xx" is a restatement of the question. The answer is
what the failing requests actually hit, which lives in the logs of a service that
may not be the one reporting the error.

## The chain

1. **`api_error_rates`** — which services are throwing 5xx, ranked. Istio mesh
   telemetry, so it covers every service including the ones with no metrics of
   their own. Those are disproportionately the ones breaking.
2. **`api_error_ratio`** — for the top candidate, what fraction of its traffic is
   failing. A rate without a denominator ranks a dead low-traffic service above a
   partial outage on a critical path.
3. **`api_error_codes`** — which 5xx. This decides where to look next, and skipping
   it is how you end up reading application logs for a problem that is not in the
   application:
   - **502 / 503** — upstream unreachable or no healthy endpoints. Go to
     `pod_status` and `recent_events`. The app logs will be empty because the app
     never received the request.
   - **504** — reached, too slow. The cause is the slow dependency, so go to the
     database and cache runbooks, not the logs.
   - **500** — the application raised. THIS is the one the logs answer. Continue.
4. **`api_error_routes`** — which endpoint. If it returns a single `unknown` bucket
   the mesh is not labelling routes; get the path from the log lines in step 5
   instead.
5. **`error_request_ids`** — request ids for the failing requests. Take two or
   three, not fifty: failures in one bucket are usually the same failure, and
   reading one properly beats skimming all of them.
6. **`logs_for_request_id`** — every line carrying that id, across all services.
   Leave `service` unset. The whole point is to see the request in services other
   than the one that reported the error.

## Reading the trace

Sort by timestamp and find the **first** failure. Everything after it is usually a
consequence. Reporting the last error in the list describes a symptom as if it were
a cause, which is the most common way this analysis goes wrong.

Name the service that failed first, quote the actual error text, and say which call
it was making. "rider-app returned 500 because its call to driver-offer-bpp timed
out after 30s" is an answer. "There are 500 errors in rider-app" is not.

## Verified names — use these, do not improvise

These are confirmed against this environment. A near-miss name returns an empty
result, and an empty result reads as "healthy", so guessing here produces
confident false negatives.

- **Metric**: `istio_requests_total`, grouped by **`destination_workload`**. Not
  `destination_service_name` — that is what a generic Istio guide says and it
  matches nothing here.
- **App-level HTTP**: `api_http_requests_duration_seconds_count` / `_bucket` /
  `_sum`, also by `destination_workload`.
- **Istio access logs**: index pattern `istio-*`. Filter `response_code >= 500`,
  sort by `@timestamp` descending. The id field is **`request_id`** or
  **`x_request_id`** depending on the index.
- **App logs**: the request id appears inside the message, so a phrase match on
  the id works even where the field is absent.
- **Sidecar fallback**: when the log store is unavailable, the istio-proxy
  container on the failing pod has the same access log — `pod_logs` with
  container `istio-proxy` and a `5` status grep gets you request ids directly.
  Use this when the ES path returns nothing but metrics clearly show 5xx.

## Traps

- **Empty is not healthy.** Every entry here returns nothing both when there are no
  errors and when a label value is wrong. Before reporting "no errors", confirm the
  service name matched something — `api_error_rates` with no filter is the check.
  Use `metric_names` if you suspect the label names themselves differ.
- **GCP unless the question names AWS.** The platform is migrating to GCP, and
  AWS logs are not reachable from this deployment at all — a call there returns a
  connection error, not an empty result. Answer from GCP and say so; only reach
  for AWS when asked, and report plainly that it could not be checked.
- **The request id must come from the same cloud as the logs you search.** Ids are
  not shared; the other cloud always returns nothing.
- **Hit counts are samples, not counts.** `error_request_ids` returns at most
  `limit` entries. Only `api_error_rates` answers "how many".
- **Counts are doubled, rankings are not.** None of these filter the `reporter`
  label, because an over-specific matcher that returns nothing is indistinguishable
  from "no errors" — the worst possible failure during an incident. Both ends of a
  call report it, so absolute rates are roughly doubled. Use them to rank and to
  compare against the same metric's own baseline, and do not quote a rate as a
  literal request count.
