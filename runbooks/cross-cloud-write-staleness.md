---
name: Cross-cloud write staleness (onRide, pool data, driver flags)
surfaces: [redis:read, db:entity, db:read, logs]
functions: [redis_get, redis_exists, redis_ttl, redis_type, driver_account_state, logs_search]
keywords: ["onride", "on ride", "stale", "wrong value", "self corrects", "cross cloud", "aws gcp differ", "redis differs from db", "driver not on ride", "pool data", "divergent", "one cloud"]
owner: infra
reviewed_on: 2026-08-19
---

A specific and recurring bug shape: **the database is correct, one cloud's Redis is
not, and it fixes itself in seconds to minutes.** Recognising it saves hours,
because every instinct points at the database and the database is never wrong here.

## The mechanism

Writes to a KV-cached table go to Redis. Two different write paths exist and they
behave differently across clouds:

- The single-row path updates **only ONE cloud** — the first Redis where the row is
  found, which is the writing pod's own. It short-circuits and never touches the
  other cloud's copy.
- The multi-row path updates the copy in **both** clouds.

Some flows are reachable from a pod whose cloud is not the driver's home cloud —
the BECKN confirm handler is the known one. When such a flow uses the single-row
path, the value is written to the *confirming pod's* cloud, and a read from the
driver's home cloud returns the old value.

Reads do not repair this. Recaching on read is off by default, and the secondary
lookup only runs on a **MISS** — a stale **HIT** never consults the other cloud.
That is why the stale value survives until something else overwrites it.

## FIRST: can you even compare the clouds here?

Verified 2026-08-19 in this deployment: **both Redis connections resolve to the
same ElastiCache instance, and the project has no Memorystore at all.** The two
clouds share one Redis.

Where that holds, the comparison below is impossible — two reads hit one
instance, always agree, and "the caches agree" is a false negative rather than a
finding. Every Redis read returns a note saying so. When you see it, say the
comparison cannot be made and stop; do not report agreement as evidence of
health.

The rest of this runbook applies where the clouds genuinely have separate Redis
instances, and to the database-versus-cache comparison, which is still valid: one
database, one cache, and a disagreement between them is real either way.

## Diagnosing it, read-only

1. `driver_account_state` — get the driver's `cloud_type` (their home cloud) and the
   database's version of the value. Treat the database as ground truth.
2. `redis_get` the key **in both clouds** and compare. Two shapes confirm this bug:
   - the key exists only in the cloud that is *not* their home cloud — a transient
     timing race, and it will self-heal;
   - the key exists in both with **different `updatedAt`** — persistent drift, which
     will not self-heal and is the one worth reporting.
3. `redis_ttl` on both. A key with no expiry holding a stale value is the worst case.

## Reporting it

Say which cloud held which value, and what the database said. "The GCP copy says
false, the AWS copy says true from three hours earlier, and the database says true"
is the finding. "The cache is stale" is not — it does not tell anyone which copy to
trust or whether it will recover.

If the two copies agree with each other and disagree with the database, this is a
**different** problem and this runbook does not apply.

## Traps

- **Never conclude from one cloud.** Checking only the home cloud makes a
  cross-cloud write invisible, and checking only the other makes a healthy driver
  look broken.
- **Self-correcting is not fixed.** These recover when the next write lands, so a
  clean re-check minutes later does not mean it did not happen. Say whether the
  drift was persistent.
- **The database is not the bug.** There is one database and no replication between
  clouds, so a difference between clouds is always a cache difference.
- Only one write path in this codebase currently carries a guard for cross-cloud
  writes; the rest do not. So this shape can appear on any KV-cached field written
  from a cross-cloud-reachable flow, not only the ones already known.
