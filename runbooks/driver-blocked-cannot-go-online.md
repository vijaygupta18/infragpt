---
name: Driver blocked, unsubscribed, or cannot go online
surfaces: [db:entity, redis:read, logs]
functions: [driver_id_from_phone_hash, driver_account_state, driver_dues_summary, driver_plan_state, redis_get, redis_exists, redis_ttl, logs_search]
keywords: ["driver blocked", "cannot go online", "not getting rides", "cleared dues", "still blocked", "payment pending", "unsubscribed", "subscription", "driver stuck", "driver id", "phone number", "dues"]
owner: infra
reviewed_on: 2026-08-19
---

The most common support escalation: a driver paid, and is still blocked. Answer it
by establishing which of three separate mechanisms is holding them, because they
have different causes and different owners.

## Order

1. **`driver_id_from_phone_hash`** — you will be given a phone number, and this
   system cannot hash it (the salt is not here). Ask for the hash, or for the
   driver id directly. Note the hash is over the bare 10-digit number with **no
   country code** — a hash built with `+91` matches nothing and looks exactly like
   "no such driver".
2. **`driver_account_state`** — the three flags, which are independent:
   - `blocked = true` — an explicit block. Read `blocked_reason` and
     `block_expiry_time`. Nothing about dues will fix this.
   - `subscribed = false` — recomputed from outstanding dues against the plan's
     credit limit. This is the "cleared dues but still blocked" case.
   - `payment_pending = true` — set only by the payment-status path.
   Also read `cloud_type`: it decides which cloud's Redis and pods are worth
   looking at at all.
3. **`driver_dues_summary`** — only `RECURRING_INVOICE` and
   `RECURRING_EXECUTION_INVOICE` in `PAYMENT_PENDING` / `PAYMENT_OVERDUE` count
   toward the threshold that unsubscribes a driver. `MANDATE_REGISTRATION` and
   `PAYOUT_REGISTRATION` rows do **not**. Counting them is the standard way to
   conclude a driver owes money when they do not.
4. **`driver_plan_state`** — `subscribed` compares dues against *the plan's* credit
   limit, so the plan is half the comparison. A driver moved to a plan with a lower
   limit can be unsubscribed with no new dues at all.

## The trap that makes this hard

`driver_information` is **KV-cached**. What the database says and what the driver's
app sees can differ, and the app is reading Redis. The Redis key is
`driverInformation_driverId_<driverId>` with a shard suffix — note camelCase, not
snake_case.

So when the database shows the driver is fine and the driver says otherwise, the
answer is usually a stale cache in their cloud, not a wrong row. Check the key in
**their registration cloud** (`cloud_type` above). Redis is per-cloud and never
replicated, so checking the other cloud proves nothing.

## What this runbook cannot do, and must say

Repairing any of this is a **write**, and nothing here can write. The useful output
is a precise diagnosis and the specific lever, named for a human to pull:

- `subscribed` is repaired by a plan switch, which recomputes it and syncs the
  location-tracking copy. A direct database fix alone can leave the driver able to
  go online but missing from the allocation pool, because that service keeps its
  own copy.
- `payment_pending` has no driver-facing lever at all.
- Order matters for whoever does it: update, **then** purge the cache. Purging first
  lets a read repopulate the stale value before the write lands.

State which flag is set, why, and which lever applies. Do not imply the assistant
can clear it.
