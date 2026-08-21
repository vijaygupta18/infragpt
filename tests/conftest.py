"""Test-wide environment.

The registry deliberately carries no deployment's namespace names — they arrive
from INFRAGPT_NAMESPACES via the ConfigMap, because this repository is
published. Without it the `namespace` enum is empty and the registry refuses to
load, which is the correct production behaviour (a misconfigured deployment
should fail to start, not start with a kubectl surface that can reach nothing).

Tests therefore have to supply one, exactly as a deployment does. The value here
is a placeholder chosen to look like a placeholder: if a real namespace name
appears in this file, the separation it exists to enforce has already been lost.
"""

from __future__ import annotations

import os

import pytest

_TEST_ENV = {
    "INFRAGPT_NAMESPACES": "apps",
    "INFRAGPT_PG_USER": "test_ro",
    "INFRAGPT_DRIVER_DB": "test_driver_db",
    "INFRAGPT_RIDER_DB": "test_rider_db",
    "GCP_PROJECT": "test-project",
    "GCP_REGION": "test-region",
    "AWS_REGION": "test-region",
    "GRID_BASE_URL": "https://gateway.invalid",
    # ClickHouse, same rule: no host or credential has a default in config, so
    # tests supply one exactly as a deployment does. `.invalid` is reserved by
    # RFC 2606 and can never resolve, so a test that accidentally tries to
    # connect fails fast rather than reaching something real.
    "INFRAGPT_CLICKHOUSE_HOST": "clickhouse.invalid",
    "INFRAGPT_CLICKHOUSE_USER": "test_ro",
    "INFRAGPT_CLICKHOUSE_DB": "test_analytics",
}


@pytest.fixture(scope="session", autouse=True)
def _base_environment() -> None:
    """Set deployment config before anything imports app.config.

    Session-scoped and autouse: app.config reads the environment at import time,
    so this has to be in place before the first test module imports it.
    """
    for key, value in _TEST_ENV.items():
        os.environ.setdefault(key, value)


# Applied at import time too — a session fixture still runs after collection has
# already imported the test modules, and those import app.config.
for _key, _value in _TEST_ENV.items():
    os.environ.setdefault(_key, _value)


@pytest.fixture(autouse=True)
def _clear_auth_throttles() -> None:
    """Throttle counters are process-global by design (single replica).

    Without this, tests leak into each other: whichever test registers the sixth
    account gets refused for a reason that has nothing to do with what it is
    checking. Resetting per test keeps the throttle real in production and
    invisible here.
    """
    from app.auth.throttle import LOGIN_THROTTLE, REGISTER_THROTTLE

    for throttle in (LOGIN_THROTTLE, REGISTER_THROTTLE):
        throttle._hits.clear()  # noqa: SLF001 - test-only reset of module state


@pytest.fixture(autouse=True)
def _isolated_runbook_dir(tmp_path_factory, monkeypatch):
    """Point runbook writes at a temp directory.

    Runbook authoring is the one write path in the application. Without this a
    test would either fail against a read-only /data or, worse, succeed and
    write into the repository's own runbooks/ — leaving fixture text that ships
    to production in the next image.
    """
    from app import config

    directory = tmp_path_factory.mktemp("runbooks")
    monkeypatch.setattr(config, "RUNBOOK_DIR", directory)
    yield directory
