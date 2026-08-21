"""Role model.

Roles are the human interface to surfaces. These tests exist because a role that
quietly grants more than its label implies is worse than no roles at all — an
admin would be relying on a description that lies.
"""

from __future__ import annotations

from app.access.roles import (
    BY_KEY,
    ROLES,
    expand,
    infer_roles,
    leftover_surfaces,
    optional_surfaces,
)
from app.registry.schema import Surface


def test_every_role_expands_to_real_surfaces() -> None:
    valid = set(Surface)
    for role in ROLES:
        assert role.surfaces, role.key
        assert set(role.surfaces) <= valid, role.key


def test_every_surface_belongs_to_some_role() -> None:
    """A surface in no role can only be granted by hand, which in practice means
    it never gets granted. Adding a surface should force the question of whose
    job needs it."""
    assert optional_surfaces() == []


def test_only_admin_grants_the_admin_surface() -> None:
    for role in ROLES:
        if role.key != "admin":
            assert Surface.ADMIN not in role.surfaces, role.key


def test_roles_are_ordered_least_to_most_privileged() -> None:
    """The list is read top-down under time pressure; the widest must be last."""
    ordered = sorted(ROLES, key=lambda r: r.order)
    assert ordered[-1].key == "admin"
    assert len(ordered[-1].surfaces) == max(len(r.surfaces) for r in ordered)


def test_there_are_exactly_three_roles() -> None:
    """Seven roles in a ladder was a finer model than anyone used: approvers
    could not tell whether a joiner was Support or Engineer, so they picked the
    larger one. The surviving split is the question people can answer instantly
    — infrastructure, data, or running the tool.
    """
    assert {r.key for r in ROLES} == {"infra", "analytics", "admin"}


def test_infra_reads_the_platform_but_not_peoples_records() -> None:
    infra = BY_KEY["infra"]
    assert Surface.METRICS in infra.surfaces
    assert Surface.K8S_GCP in infra.surfaces
    assert Surface.DB_READ in infra.surfaces, "database health is infra work"
    assert Surface.DB_ENTITY not in infra.surfaces, "per-person records are not"
    assert Surface.ANALYTICS not in infra.surfaces


def test_analytics_reaches_the_data_and_says_so() -> None:
    analytics = BY_KEY["analytics"]
    assert Surface.ANALYTICS in analytics.surfaces
    assert Surface.DB_ENTITY in analytics.surfaces
    assert "pii" in analytics.tags
    assert analytics.caution, "the role that returns customer records must warn"


def test_admin_is_the_union_of_the_other_two() -> None:
    admin = set(BY_KEY["admin"].surfaces)
    assert set(BY_KEY["infra"].surfaces) <= admin
    assert set(BY_KEY["analytics"].surfaces) <= admin
    assert Surface.ADMIN in admin


def test_every_role_carries_a_caution() -> None:
    """With only three roles, each one is broad enough to be worth a warning at
    grant time. There is no longer a 'safe' role that needs none."""
    for role in ROLES:
        assert role.caution, role.key


def test_expand_ignores_unknown_roles_rather_than_failing_open() -> None:
    """A role key that no longer exists — a rename, a stale bookmark — must
    grant nothing, never everything."""
    assert expand(["nonsense"]) == set()
    assert expand(["viewer"]) == set(), "a role removed in the 3-role collapse"
    assert expand(["analytics", "nonsense"]) == set(BY_KEY["analytics"].surfaces)


def test_infer_roles_reports_contained_roles_only() -> None:
    """Holding every Infra surface should read back as Infra — and must not
    claim Analytics, which it does not cover."""
    keys = {r.key for r in infer_roles(set(BY_KEY["infra"].surfaces))}
    assert "infra" in keys
    assert "analytics" not in keys
    assert "admin" not in keys


def test_leftover_surfaces_are_shown_not_hidden() -> None:
    """A hand-picked grant that matches no role must still be visible, or the UI
    would under-report what someone can actually see."""
    held = {Surface.METRICS, Surface.DB_READ}
    assert Surface.DB_READ in leftover_surfaces(held)


def test_admin_covers_every_surface_including_future_ones() -> None:
    """Admin is derived from the Surface enum, not hand-listed.

    The list previously said "Everything" while omitting analytics and
    shell:read, so an admin asking an analytics question was told no function
    existed — a confusing refusal for someone who could grant it to themselves
    in the next click. Withholding a surface from Admin was never a security
    boundary; this role can widen its own access by definition.
    """
    admin = BY_KEY["admin"]
    assert set(admin.surfaces) == set(Surface), (
        "a surface exists that Admin does not cover — derive, do not hand-list"
    )
