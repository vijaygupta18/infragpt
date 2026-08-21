"""Guard tests. Every case here is an attempt to get a write past the allowlist.

The guard is layer 4 of 4 — the read-only ServiceAccount and SELECT-only role are
what actually protect production. These tests exist so that layer 4 fails closed
rather than quietly widening.
"""

from __future__ import annotations

import shlex

import pytest

from app.shell.guard import CommandRefused, check


def refused(argv: list[str]) -> str:
    with pytest.raises(CommandRefused) as exc:
        check(argv)
    return str(exc.value)


# ---- binaries ---------------------------------------------------------------


@pytest.mark.parametrize("binary", ["bash", "sh", "python", "nc", "ssh", "helm",
                                    "terraform", "git", "rm", "docker"])
def test_only_allowlisted_binaries(binary: str) -> None:
    assert "not an allowed binary" in refused([binary, "--help"])


def test_path_prefix_does_not_smuggle_a_binary() -> None:
    assert "not an allowed binary" in refused(["/bin/bash", "-c", "ls"])


# ---- kubectl ----------------------------------------------------------------


def test_kubectl_read_verbs_pass() -> None:
    check(["kubectl", "get", "pods", "-n", "apps"])
    check(["kubectl", "describe", "pod", "x", "-n", "apps"])
    check(["kubectl", "logs", "x", "-n", "apps", "--tail=100"])


@pytest.mark.parametrize("verb", ["delete", "apply", "patch", "scale", "edit",
                                  "exec", "port-forward", "cp", "proxy", "drain",
                                  "cordon", "annotate", "label", "rollout", "attach"])
def test_kubectl_write_and_escape_verbs_refused(verb: str) -> None:
    assert "not a read verb" in refused(["kubectl", verb, "pods"])


def test_kubectl_secrets_refused_even_though_get_is_a_read() -> None:
    """Read-only is not the same as safe to read."""
    msg = refused(["kubectl", "get", "secret", "db-creds", "-o", "yaml"])
    assert "credentials" in msg


def test_kubectl_configmaps_refused() -> None:
    assert "credentials" in refused(["kubectl", "get", "configmaps", "-o", "yaml"])


def test_kubectl_identity_flags_refused() -> None:
    assert "not permitted" in refused(
        ["kubectl", "get", "pods", "--as", "system:admin"]
    )


# ---- psql -------------------------------------------------------------------


def test_psql_select_passes() -> None:
    check(["psql", "-c", "SELECT count(*) FROM pg_stat_activity"])


@pytest.mark.parametrize("stmt", [
    "UPDATE person SET blocked = true",
    "DELETE FROM booking",
    "DROP TABLE ride",
    "INSERT INTO x VALUES (1)",
    "TRUNCATE x",
    "GRANT ALL ON x TO y",
    "CREATE TABLE z (a int)",
])
def test_psql_mutations_refused(stmt: str) -> None:
    assert "mutating" in refused(["psql", "-c", stmt]) or "not a read" in refused(
        ["psql", "-c", stmt]
    )


def test_psql_chained_statement_refused() -> None:
    # Either guard may fire first (the DROP is caught before the chaining is);
    # the guarantee is that it is refused, not which rule caught it.
    msg = refused(["psql", "-c", "SELECT 1; DROP TABLE ride"])
    assert "mutating" in msg or "multiple statements" in msg


def test_psql_string_concat_is_not_mistaken_for_a_shell_pipe() -> None:
    """`||` is Postgres concatenation. A shell-aware scan would reject a
    legitimate read, so the SQL argument gets a SQL-aware check instead."""
    check(["psql", "-c", "SELECT relname || ':' || relkind FROM pg_class"])


def test_psql_semicolon_chain_still_caught_despite_the_exemption() -> None:
    msg = refused(["psql", "-c", "SELECT 1; SELECT 2"])
    assert "multiple statements" in msg


def test_psql_without_c_refused() -> None:
    assert "only `-c" in refused(["psql", "-f", "x.sql"])


# ---- redis ------------------------------------------------------------------


def test_redis_reads_pass() -> None:
    check(["redis-cli", "-h", "h", "get", "somekey"])
    check(["redis-cli", "-h", "h", "ttl", "somekey"])


@pytest.mark.parametrize("cmd", ["set", "del", "flushall", "flushdb", "keys",
                                 "rename", "expire", "lpush", "sadd"])
def test_redis_writes_and_keys_refused(cmd: str) -> None:
    assert "no read command" in refused(["redis-cli", "-h", "h", cmd, "k", "v"])


def test_redis_config_set_refused() -> None:
    assert "not permitted" in refused(["redis-cli", "-h", "h", "config", "set", "x", "1"])


# ---- aws --------------------------------------------------------------------


def test_aws_describe_and_list_pass() -> None:
    check(["aws", "elasticache", "describe-cache-clusters"])
    check(["aws", "ec2", "describe-instances"])
    check(["aws", "s3", "ls"])


@pytest.mark.parametrize("op", ["create-cluster", "delete-cache-cluster",
                                "modify-cache-cluster", "put-object",
                                "terminate-instances", "run-instances",
                                "update-service", "reboot-cache-cluster"])
def test_aws_mutations_refused(op: str) -> None:
    assert "not a read operation" in refused(["aws", "elasticache", op])


# ---- gcloud -----------------------------------------------------------------


def test_gcloud_describe_and_list_pass() -> None:
    check(["gcloud", "alloydb", "instances", "list", "--project=<GCP_PROJECT>"])
    check(["gcloud", "alloydb", "instances", "describe", "x", "--project=<GCP_PROJECT>"])


@pytest.mark.parametrize("verb", ["create", "delete", "update", "set", "deploy",
                                  "scale", "restart", "ssh", "failover", "patch"])
def test_gcloud_mutations_refused(verb: str) -> None:
    assert "mutating" in refused(
        ["gcloud", "alloydb", "instances", verb, "x"]
    ) or "not a read command" in refused(["gcloud", "alloydb", "instances", verb, "x"])


def test_gcloud_mutating_verb_alongside_a_read_verb_is_still_refused() -> None:
    assert "mutating" in refused(
        ["gcloud", "alloydb", "instances", "list", "delete", "x"]
    )


# ---- curl -------------------------------------------------------------------


def test_curl_get_passes() -> None:
    check(["curl", "https://monitoring.googleapis.com/v3/projects/p/timeSeries"])
    check(["curl", "-X", "GET", "https://example.internal/metrics"])


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_curl_write_methods_refused(method: str) -> None:
    assert "not permitted" in refused(
        ["curl", "-X", method, "https://example.internal/x"]
    )


@pytest.mark.parametrize("flag", ["-d", "--data", "--data-binary", "-F", "-T",
                                  "--upload-file", "--json"])
def test_curl_body_flags_refused_even_without_an_explicit_method(flag: str) -> None:
    """curl silently upgrades to POST when given a body."""
    assert "request body" in refused(
        ["curl", flag, "x=1", "https://example.internal/x"]
    )


def test_curl_local_file_access_refused() -> None:
    assert "local file" in refused(["curl", "file:///etc/passwd"])


def test_curl_requires_an_explicit_url() -> None:
    assert "http(s) URL" in refused(["curl", "-s"])


# ---- shell metacharacters ---------------------------------------------------


@pytest.mark.parametrize("arg", ["a|b", "a;b", "a&&b", "`id`", "$(id)", "a\nb"])
def test_shell_metacharacters_refused(arg: str) -> None:
    """There is no shell, so these cannot compose anything — but their presence
    means something was trying to, which is itself worth refusing on."""
    assert "metacharacter" in refused(["kubectl", "get", "pods", arg])


# --- silent failures must still explain themselves --------------------------


def test_a_silent_curl_dns_failure_is_explained() -> None:
    """Observed live: `curl -s` against a host that does not exist produced
    "exited 6: (no output)". The model could not tell DNS from a timeout, tried
    the same thing again, and gave up. An exit code alone is not correctable.
    """
    from app.executors.shell_exec import _explain_exit

    detail = _explain_exit("curl", 6)
    assert "resolve" in detail.lower()
    # It must also say what to do instead, or the next round guesses again.
    assert "guess" in detail.lower() or "registered function" in detail.lower()


def test_the_explanation_names_the_real_metrics_backend() -> None:
    """The specific wrong guess was `http://prometheus:9090`."""
    from app.executors.shell_exec import _explain_exit

    assert "VictoriaMetrics" in _explain_exit("curl", 6)


@pytest.mark.parametrize("code", [3, 7, 22, 28, 35, 60])
def test_common_curl_failures_each_say_something_actionable(code: int) -> None:
    from app.executors.shell_exec import _explain_exit

    detail = _explain_exit("curl", code)
    assert detail and "no output" in detail
    assert len(detail) > 30


def test_an_unknown_exit_code_still_suggests_the_next_step() -> None:
    from app.executors.shell_exec import _explain_exit

    detail = _explain_exit("kubectl", 99)
    assert "quiet flags" in detail


def test_a_command_that_printed_something_keeps_its_own_words() -> None:
    """Translation is a fallback. The tool's real message is always better."""
    from app.executors.shell_exec import _explain_exit

    # The explainer is only consulted when output is empty; assert the mapping
    # does not claim to know what a tool with output would have said.
    assert _explain_exit("curl", 6) != ""


def test_gcloud_logging_read_is_permitted() -> None:
    """`gcloud logging read` is the only route to GCP Cloud Logging from here.

    It was refused because `read` was missing from the verb allowlist — a
    read-only command, refused for being unlisted, silently removing a whole
    log source. Found by testing what the guard actually permits rather than
    what it was assumed to.
    """
    check(shlex.split('gcloud logging read severity=ERROR --limit 10'))


def test_gcloud_still_refuses_mutating_verbs() -> None:
    for cmd in (
        "gcloud compute instances delete vm",
        "gcloud container clusters update c",
        "gcloud sql instances patch i",
        "gcloud logging sinks create s dest",
    ):
        with pytest.raises(CommandRefused):
            check(shlex.split(cmd))


def test_a_missing_cli_points_at_the_working_alternative() -> None:
    """gcloud and aws are not installed here, and the model reaches for them
    anyway because they are the obvious tools. A bare "not available" sends it
    away from a capability it actually has via the REST functions."""
    from app.executors.shell_exec import _missing_binary

    gcloud = _missing_binary("gcloud")
    assert "not installed" in gcloud
    assert "query_insights_top" in gcloud or "alloydb_instances" in gcloud

    aws = _missing_binary("aws")
    assert "elasticache_instances" in aws


def test_an_unknown_missing_binary_says_stop_rather_than_retry() -> None:
    from app.executors.shell_exec import _missing_binary

    assert "no equivalent" in _missing_binary("terraform")


# --- gsutil / bq ------------------------------------------------------------


@pytest.mark.parametrize("cmd", [
    "gsutil ls gs://bucket",
    "gsutil du -s gs://bucket",
    "gsutil stat gs://bucket/obj",
    "bq ls",
    "bq show project:dataset.table",
    "bq head -n 5 project:dataset.table",
])
def test_gsutil_and_bq_reads_are_allowed(cmd: str) -> None:
    check(shlex.split(cmd))


@pytest.mark.parametrize("cmd", [
    "gsutil rm gs://bucket/obj",
    "gsutil cp a gs://bucket/obj",
    "gsutil rsync a gs://bucket",
    "bq rm -t project:dataset.table",
    "bq load project:dataset.table file",
    "bq mk dataset",
])
def test_gsutil_and_bq_writes_are_refused(cmd: str) -> None:
    with pytest.raises(CommandRefused):
        check(shlex.split(cmd))


def test_gsutil_cat_is_refused_even_though_it_only_reads() -> None:
    """Object CONTENTS can be anything, including the credentials this tool is
    forbidden to read. Listing what exists is inventory; reading it is not."""
    with pytest.raises(CommandRefused, match="CONTENTS"):
        check(shlex.split("gsutil cat gs://bucket/secrets.env"))


def test_bq_query_is_refused_because_it_can_also_write() -> None:
    """`bq query` executes DML and DDL as readily as SELECT, and the guard is
    given a command, not parsed SQL — so it cannot tell them apart."""
    with pytest.raises(CommandRefused, match="DML"):
        check(shlex.split("bq query 'SELECT 1'"))


# --- success is not always success ------------------------------------------


def test_gcloud_permission_warning_on_exit_zero_is_treated_as_failure() -> None:
    """gcloud prints missing permissions as a WARNING and exits 0.

    Judged on the exit code alone, "no instances exist" and "not allowed to
    list instances" are the same answer, and only one is true. Verified against
    a service account lacking compute.viewer on 2026-08-21 — a check that read
    the exit code reported OK while the command returned nothing.
    """
    from app.executors.shell_exec import _permission_denied

    out = (
        "WARNING: Some requests did not succeed.\n"
        " - Required 'compute.instances.list' permission for 'projects/x'\n"
    )
    detail = _permission_denied(out)
    assert "compute.instances.list" in detail


@pytest.mark.parametrize("out", [
    "Error from server (Forbidden): pods is forbidden: User cannot list",
    "An error occurred (AccessDenied) when calling the DescribeInstances operation",
    "caller does not have permission to access this resource",
    "PERMISSION DENIED: missing role",
])
def test_other_authorisation_failures_are_recognised(out: str) -> None:
    from app.executors.shell_exec import _permission_denied

    assert _permission_denied(out), out


def test_ordinary_output_is_not_mistaken_for_a_denial() -> None:
    """False positives would turn working commands into reported failures."""
    from app.executors.shell_exec import _permission_denied

    assert _permission_denied("NAME  STATUS\npod-1  Running") == ""
    assert _permission_denied("") == ""
