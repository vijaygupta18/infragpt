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
    # THREE ROLES, deliberately.
    #
    # There were seven, arranged in a ladder with two side roles. It was a finer
    # model than anyone actually uses: approvers do not know whether a new
    # joiner is "Support" or "Engineer", so they pick the larger one, and the
    # extra granularity buys nothing while making every grant a small decision.
    #
    # The split that survives is the one people can answer instantly: does this
    # person work on INFRASTRUCTURE, on DATA, or do they run the tool?
    Role(
        key="infra",
        label="Infra",
        summary="Read everything about how the platform is running.",
        surfaces=(
            Surface.METRICS,
            Surface.LOGS,
            Surface.K8S_GCP,
            Surface.K8S_AWS,
            Surface.REDIS_READ,
            Surface.CLOUD_GCP,
            Surface.CLOUD_AWS,
            Surface.DB_READ,
            Surface.CODE,
            Surface.SHELL_READ,
        ),
        grants_you=(
            "Metrics, logs, Kubernetes, caches and cloud control planes",
            "Database health — indexes, locks, replication, live queries",
            "The source code, to explain WHY an error happens",
            "Running read-only commands it composes when no function fits",
        ),
        caution=(
            "Includes db:read, which is database METADATA only — schema, "
            "indexes, statistics — and cannot reach application rows. It also "
            "includes self-composed read commands, which is the widest single "
            "capability here; everything it can reach is still bounded by "
            "read-only credentials."
        ),
        order=10,
    ),
    Role(
        key="analytics",
        label="Analytics",
        summary="Query the data itself — rides, bookings, and per-person records.",
        surfaces=(
            Surface.ANALYTICS,
            Surface.DB_READ,
            Surface.DB_ENTITY,
            Surface.METRICS,
        ),
        grants_you=(
            "ClickHouse — ride, booking and event data",
            "Database schema, indexes and statistics",
            "Per-subject lookups for one driver or rider at a time",
        ),
        caution=(
            "This role returns REAL PEOPLE'S DATA. Per-subject lookups are "
            "capped to a single identified subject and every one is written to "
            "the audit log with the identifier used — but this is the role "
            "where customer records are in scope at all."
        ),
        order=20,
        tags=("pii",),
    ),
    Role(
        key="admin",
        label="Admin",
        summary="Everything, plus approving people and assigning roles.",
        # DERIVED from the enum, not hand-listed. The list previously said
        # "Everything" while omitting two surfaces, so an admin asking an
        # analytics question was told no function existed — a confusing refusal
        # for someone who could grant it to themselves in the next click.
        #
        # Withholding a surface from Admin was never a security boundary: this
        # role widens its own access by definition. It only made the product lie
        # about itself, and drift every time a surface was added.
        surfaces=tuple(Surface),
        grants_you=(
            "Everything Infra and Analytics cover, together",
            "Approve and disable accounts, and assign roles",
            "The full audit log",
        ),
        caution=(
            "Total read access, including real people's records, plus the "
            "ability to widen anyone else's. Keep the number of admins small — "
            "that, not a short surface list, is the control."
        ),
        order=30,
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
