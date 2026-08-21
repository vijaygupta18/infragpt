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
    """The list is read top-down under time pressure; the safe option must be
    first and the widest one last."""
    ordered = sorted(ROLES, key=lambda r: r.order)
    assert ordered[0].key == "viewer"
    assert ordered[-1].key == "admin"
    sizes = [len(r.surfaces) for r in ordered]
    assert sizes[0] == min(sizes)
    assert sizes[-1] == max(sizes)


def test_viewer_is_the_narrowest_role() -> None:
    assert set(BY_KEY["viewer"].surfaces) == {Surface.METRICS}


def test_support_adds_logs_and_says_why_that_matters() -> None:
    support = BY_KEY["support"]
    assert Surface.LOGS in support.surfaces
    # Logs are the first place user data appears; an approver must be told.
    assert support.caution
    assert "personal data" in support.caution.lower()


def test_engineer_covers_support() -> None:
    """Roles should nest, so 'more senior' never means 'loses something'."""
    assert set(BY_KEY["support"].surfaces) <= set(BY_KEY["engineer"].surfaces)


def test_admin_covers_engineer() -> None:
    assert set(BY_KEY["engineer"].surfaces) <= set(BY_KEY["admin"].surfaces)


def test_roles_carrying_real_risk_carry_a_caution() -> None:
    for key in ("support", "engineer", "analyst", "admin"):
        assert BY_KEY[key].caution, key


def test_expand_ignores_unknown_roles_rather_than_failing_open() -> None:
    assert expand(["nonsense"]) == set()
    assert expand(["viewer", "nonsense"]) == {Surface.METRICS}


def test_infer_roles_reports_contained_roles_only() -> None:
    held = set(BY_KEY["support"].surfaces)
    keys = {r.key for r in infer_roles(held)}
    assert "viewer" in keys and "support" in keys
    assert "engineer" not in keys


def test_leftover_surfaces_are_shown_not_hidden() -> None:
    """A hand-picked grant that matches no role must still be visible, or the UI
    would under-report what someone can actually see."""
    held = {Surface.METRICS, Surface.DB_READ}
    assert Surface.DB_READ in leftover_surfaces(held)
