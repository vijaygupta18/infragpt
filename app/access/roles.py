"""Roles — the unit people are actually granted.

Surfaces are the enforcement primitive; roles are the human interface to them.
Handing an admin nine checkboxes and asking which ones a new joiner needs
guarantees one of two outcomes, and both are bad: everything gets ticked because
that is the safe-feeling default, or the request bounces back and forth for a
week. Neither produces least privilege.

A role answers the question an admin can actually answer — "what does this person
do?" — and the mapping from job to surfaces is made once, here, by someone who
knows the blast radius, rather than repeatedly at the point of approval.

Surfaces remain the thing enforced. A role is only ever expanded into surfaces at
grant time, so there is no second permission system to keep in sync, and a role
can be changed later without touching the enforcement path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.registry.schema import Surface


@dataclass(frozen=True)
class Role:
    key: str
    label: str
    summary: str
    surfaces: tuple[Surface, ...]
    #: Shown at grant time. Say what the holder can SEE, in their words, not ours.
    grants_you: tuple[str, ...] = ()
    #: Anything an approver should weigh before clicking. Empty for the safe ones.
    caution: str = ""
    order: int = 0
    tags: tuple[str, ...] = field(default_factory=tuple)


ROLES: tuple[Role, ...] = (
    Role(
        key="viewer",
        label="Viewer",
        summary="Service health and dashboards. The safe default for anyone new.",
        surfaces=(Surface.METRICS,),
        grants_you=(
            "Error rates, latency and saturation for any service",
            "Cluster and database capacity metrics",
        ),
        order=10,
        tags=("safe-default",),
    ),
    Role(
        key="support",
        label="Support",
        summary="Answer 'is it us or is it them' without touching infrastructure.",
        surfaces=(Surface.METRICS, Surface.LOGS),
        grants_you=(
            "Everything Viewer covers",
            "Application logs, searchable by service and time",
        ),
        caution=(
            "Logs can contain personal data. It is redacted before display — "
            "phone numbers hashed, coordinates coarsened — but this is the first "
            "role where user data is in scope at all."
        ),
        order=20,
    ),
    Role(
        key="engineer",
        label="Engineer",
        summary=(
            "Full read-only debugging across both clouds. "
            "The working default for the infra team."
        ),
        surfaces=(
            Surface.METRICS,
            Surface.LOGS,
            Surface.K8S_GCP,
            Surface.K8S_AWS,
            Surface.DB_READ,
            Surface.REDIS_READ,
            Surface.CLOUD_GCP,
            Surface.CLOUD_AWS,
        ),
        grants_you=(
            "Everything Support covers",
            "Pods, logs, events and workloads in both clusters",
            "Database schema, indexes and performance metadata",
            "Redis key lookups in either cloud",
            "Cloud capacity: AlloyDB, GKE, ElastiCache",
        ),
        caution=(
            "Redis is the one surface where read-only is enforced by this "
            "application rather than by the credential, because Redis AUTH has no "
            "read-only user. Weigh that before granting it broadly."
        ),
        order=30,
    ),
    Role(
        key="analyst",
        label="Analyst",
        summary="Query business data in ClickHouse. Separate from infra debugging on purpose.",
        surfaces=(Surface.METRICS, Surface.ANALYTICS),
        grants_you=(
            "Everything Viewer covers",
            "Read queries against ClickHouse, including ride and business data",
            "ClickHouse schema and cluster health — tables, columns, parts, disks",
        ),
        caution=(
            "This is the only role that returns real business data. It is "
            "deliberately not bundled with Engineer: needing to debug a cluster "
            "is not a reason to be able to read customer records."
        ),
        order=40,
        tags=("pii",),
    ),
    Role(
        key="casework",
        label="Casework",
        summary=(
            "Look up one named driver or rider. For working a ticket, not for "
            "debugging infrastructure."
        ),
        # Deliberately OFF the Viewer -> Support -> Engineer -> Admin ladder,
        # for the same reason Analyst is. Those roles nest, so anything added to
        # Support silently lands in Engineer too — and "I debug the cluster" is
        # not a reason to be able to read a driver's record. Someone who works
        # tickets gets this role explicitly, in addition to whichever ladder
        # role they hold.
        surfaces=(Surface.METRICS, Surface.DB_ENTITY),
        grants_you=(
            "Everything Viewer covers",
            "Curated lookups for a single driver or rider — account and "
            "subscription flags, blocking reasons, recent payment state",
        ),
        caution=(
            "This returns one real person's records. Lookups are by hashed "
            "phone number or id, are capped to a single subject, and every one "
            "is written to the audit log with the identifier used."
        ),
        order=45,
        tags=("pii",),
    ),
    Role(
        key="operator",
        label="Operator",
        summary="Engineer, plus composing read-only commands when no function fits.",
        surfaces=(
            Surface.METRICS,
            Surface.LOGS,
            Surface.K8S_GCP,
            Surface.K8S_AWS,
            Surface.DB_READ,
            Surface.REDIS_READ,
            Surface.CLOUD_GCP,
            Surface.CLOUD_AWS,
            Surface.SHELL_READ,
        ),
        grants_you=(
            "Everything Engineer covers",
            "Running read-only kubectl, gcloud, aws, psql, redis-cli and curl "
            "commands it writes itself, when no registered function fits",
        ),
        caution=(
            "The widest grant here. Every other surface is a fixed catalogue "
            "someone reviewed; this one lets the assistant compose commands. It "
            "still cannot write — the pod holds viewer-only cloud roles, a "
            "get/list/watch ServiceAccount and a SELECT-only database role — but "
            "it can read anything those credentials can reach, and it is the one "
            "grant whose safety rests on the credentials rather than on a "
            "reviewed list."
        ),
        order=50,
        tags=("wide",),
    ),
    Role(
        key="admin",
        label="Admin",
        summary="Everything, plus approving people and reading the audit log.",
        surfaces=(
            Surface.ADMIN,
            Surface.METRICS,
            Surface.LOGS,
            Surface.K8S_GCP,
            Surface.K8S_AWS,
            Surface.DB_READ,
            Surface.REDIS_READ,
            Surface.CLOUD_GCP,
            Surface.CLOUD_AWS,
            Surface.DB_ENTITY,
        ),
        grants_you=(
            "Everything Engineer covers",
            "Approve and disable accounts, and change what others can see",
            "The full audit log",
        ),
        caution="Admins can widen their own access. Keep this list short.",
        order=90,
    ),
)

BY_KEY: dict[str, Role] = {r.key: r for r in ROLES}


def optional_surfaces() -> list[Surface]:
    """Surfaces that exist but are in no role, so they must be granted explicitly.

    A surface reaching this list is a prompt, not a bug: it means someone added a
    capability and has not yet decided whose job needs it.
    """
    in_roles = {s for r in ROLES for s in r.surfaces}
    return [s for s in Surface if s not in in_roles]


def expand(role_keys: list[str]) -> set[Surface]:
    """Roles -> the surfaces actually granted. The only place this mapping happens."""
    out: set[Surface] = set()
    for key in role_keys:
        role = BY_KEY.get(key)
        if role is None:
            continue
        out.update(role.surfaces)
    return out


def infer_roles(surfaces: set[Surface]) -> list[Role]:
    """Best-fit roles for a set of surfaces, for displaying an existing user.

    Approximate by design: someone may hold a hand-picked set that matches no
    role. The UI shows the roles fully contained by what they hold, and lists
    anything left over separately, rather than pretending the fit is exact.
    """
    return [r for r in ROLES if r.surfaces and set(r.surfaces) <= surfaces]


def leftover_surfaces(surfaces: set[Surface]) -> list[Surface]:
    covered = {s for r in infer_roles(surfaces) for s in r.surfaces}
    return sorted(surfaces - covered, key=lambda s: s.value)


__all__ = [
    "BY_KEY",
    "ROLES",
    "Role",
    "expand",
    "infer_roles",
    "leftover_surfaces",
    "optional_surfaces",
]
