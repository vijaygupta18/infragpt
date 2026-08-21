---
name: Replication lag and connection pressure
surfaces: [db:read]
functions: [replication_lag, active_connections, long_running_queries, locks]
keywords: ["replication lag", "replica behind", "connections", "too many connections", "connection pool", "locks", "blocked", "idle in transaction"]
owner: infra
reviewed_on: 2026-08-13
---

## Replication lag

`replication_lag` against the reader. Lag usually follows either a long-running
write transaction on the primary or a burst of bulk writes. Because reads at the platform are served from readers, lag presents to users as "I updated it but it did
not change" rather than as an error.

## Connection pressure

1. `active_connections` — compare against the pool ceiling, and note the split
   between active and idle.
2. `long_running_queries` — a query running far longer than its peers is often the
   thing holding connections open.
3. `locks` — a blocked chain means one transaction is holding a lock others need.
   Report the blocking query, not just the blocked ones; the blocked list is the
   symptom.

Watch specifically for `idle in transaction`. Those hold both a connection and any
locks taken, and they are almost always an application bug rather than load.

## AlloyDB specifics

Connections pin per node on autoscale. Adding a node does not redistribute existing
connections, so an autoscale event will not relieve pressure on connections that
are already established — only new connections benefit.
