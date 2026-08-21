---
name: Redis cross-cloud staleness
surfaces: [redis:read]
functions: [redis_exists, redis_ttl, redis_get, redis_type, redis_hgetall]
keywords: ["redis stale", "cache stale", "wrong value", "cross cloud", "key missing", "stale cache", "kv cache", "pool data"]
owner: infra
reviewed_on: 2026-08-13
---

> **GCP unless asked otherwise.** Cloud parameters default to gcp and this
> platform is migrating to GCP; only query AWS when the question names it.
>
> **Check this first.** In this deployment the two Redis connections point at the
> SAME instance (verified 2026-08-19; there is no Memorystore in the project), so
> a cross-cloud comparison is not possible — two reads are one read and will
> always agree. Every Redis read returns a note when this is the case. Report
> that the comparison cannot be made; agreement here is not evidence of health.


Redis is **per-cloud and never replicated**. The same key can hold different values
in AWS and GCP, or exist in one and not the other. This is the single most common
source of "it works for some users and not others".

## Always check both clouds

For any cache question, run the check against `cloud: gcp` **and** `cloud: aws` and
compare. A single-cloud answer to a cache question is misleading by construction.

Compare in this order:
1. `redis_exists` in both — presence asymmetry is itself the finding.
2. `redis_ttl` in both — a key alive in one cloud and expired in the other explains
   intermittent behaviour that looks random from the outside.
3. `redis_get` / `redis_hgetall` in both — differing values mean writes landed in
   one cloud only.

## Why divergence happens

- Updates are applied only in the Redis where the data was found. There is no
  sync back to the other cloud.
- The secondary Redis is consulted **only on a miss**. A stale-but-present value in
  the primary is returned without ever checking the secondary, so staleness is
  sticky rather than self-healing.
- Unguarded write paths in application code can update one cloud only. A known
  instance of this affects ride-state updates.

## Known history

A stuck `driver-pool-data` key in the location service caused a routing incident.
The key existing with a stale value in one cloud was the whole failure.
