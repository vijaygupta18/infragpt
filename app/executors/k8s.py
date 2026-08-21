"""kubectl executor — argv lists only, never a shell.

The single most important line in this file is the call to
``asyncio.create_subprocess_exec`` with a **list**. There is no shell in the
path: no ``shell=True``, no ``os.system``, no joined command string. A parameter
containing ``;``, ``$(...)`` or a backtick is therefore inert — it is passed to
kubectl as one literal argv element and there is nothing to interpret it.

Three further checks, each independent of the YAML:

* ``VERB_ALLOWLIST`` — argv[0] must be a read verb. Enforced here, not just in
  the registry, so a bad registry PR cannot introduce ``delete``.
* ``_ARG_RE`` — every substituted value must look like a Kubernetes object name.
  This is what stops a pod name beginning with ``-`` from being read by kubectl
  as a flag (argv injection without a shell).
* ``--context`` is always resolved from a named connection. The LLM never
  supplies a context, a kubeconfig or a server URL.

The real enforcement is RBAC: the ServiceAccount holds get/list/watch only.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
from pathlib import Path
from typing import Any

from app import config
from app.executors.base import MAX_OUTPUT_BYTES, ExecResult, Executor, ExecutorError
from app.registry.loader import PLACEHOLDER_RE
from app.registry.schema import RegistryEntry

#: Read verbs only. Enforced in code, independently of the registry YAML.
VERB_ALLOWLIST: frozenset[str] = frozenset(
    {"get", "list", "describe", "logs", "top", "events", "version"}
)

#: Substituted values must look like Kubernetes object names. Crucially this
#: forbids a leading '-', which is how an argv element becomes a flag.
_ARG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,252}$", re.IGNORECASE)

#: Sentinel meaning "use the pod's own in-cluster ServiceAccount", i.e. do not
#: pass --context at all. Set GKE_PROD_CONTEXT to this when deployed into the
#: cluster it should query.
IN_CLUSTER = "in-cluster"

#: Sentinel for "reach EKS directly, with a token minted from our AWS identity".
#: Set the AWS k8s connection's context to this instead of a kubeconfig context.
#: Nothing is stored: the endpoint and CA come from eks:DescribeCluster, and the
#: bearer token is a presigned STS URL valid for 60 seconds.
EKS_DIRECT = "eks-direct"

#: Where the AWS kubeconfig is mounted, when it is mounted at all. Applied
#: per-invocation rather than as a container-wide KUBECONFIG: setting that env
#: globally makes kubectl use the file INSTEAD of in-cluster config, so an absent
#: file silently redirects every GCP query to localhost:8080.
KUBECONFIG_PATH = os.getenv("INFRAGPT_KUBECONFIG", "/kubeconfig/config")

#: Where Kubernetes projects the pod's own credentials.
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
SA_TOKEN = f"{SA_DIR}/token"  # noqa: S105 - a path, not a credential
SA_CA = f"{SA_DIR}/ca.crt"


_EKS_DETAILS: dict[str, tuple[str, str]] = {}


def _eks_cluster_details(name: str, region: str) -> tuple[str, str]:
    """Endpoint and base64 CA for an EKS cluster, from eks:DescribeCluster.

    Cached for the process: a cluster's endpoint and CA do not change, and
    describing it on every kubectl call would add a round trip to AWS in front
    of every question.
    """
    if name in _EKS_DETAILS:
        return _EKS_DETAILS[name]

    from app.executors.awsapi import aws_get_json

    payload = aws_get_json("eks", region, f"/clusters/{name}")
    cluster = payload.get("cluster") or {}
    endpoint = str(cluster.get("endpoint") or "")
    ca = str((cluster.get("certificateAuthority") or {}).get("data") or "")
    if not endpoint or not ca:
        raise ExecutorError(
            f"eks:DescribeCluster returned no endpoint/CA for '{name}'. Check the "
            f"cluster name and that the role has eks:DescribeCluster."
        )
    _EKS_DETAILS[name] = (endpoint, ca)
    return endpoint, ca


def eks_direct_flags() -> list[str]:
    """Server, CA and bearer token for the AWS cluster, resolved at call time.

    kubectl is given everything explicitly rather than a kubeconfig, for the
    same reason the in-cluster path is: there is no file to keep in sync, and
    nothing long-lived is written to disk. The token lives 60 seconds.

    The CA is written to a private temp file because kubectl takes a path, not
    the certificate itself. It is public data — a CA certificate is not a
    secret — but it is still written 0600 and replaced each call rather than
    cached, so nothing accumulates in the container.
    """
    import tempfile

    from app import config
    from app.executors.awsapi import _creds
    from app.executors.ekstoken import eks_token

    name = config.EKS_CLUSTER_NAME
    region = config.AWS_REGION
    if not name:
        raise ExecutorError(
            "EKS access is not configured: set INFRAGPT_EKS_CLUSTER. Without "
            "it there is no cluster to describe and no token to mint."
        )

    endpoint, ca_data = _eks_cluster_details(name, region)
    key, secret, session = _creds()
    token = eks_token(name, region, key, secret, session)

    ca_path = Path(tempfile.gettempdir()) / f"eks-ca-{name}.crt"
    ca_path.write_bytes(base64.b64decode(ca_data))
    ca_path.chmod(0o600)

    return [
        "--server", endpoint,
        "--certificate-authority", str(ca_path),
        "--token", token,
    ]


def in_cluster_flags() -> list[str]:
    """Explicit connection flags for the pod's own cluster.

    kubectl does NOT pick up in-cluster credentials by itself. Unlike client-go,
    which falls back to rest.InClusterConfig(), kubectl only ever reads a
    kubeconfig — and with none present it defaults to localhost:8080 and fails
    with "connection refused", which reads like a cluster outage rather than a
    configuration problem. So the credentials the pod already has must be passed
    explicitly.

    These values come from the projected ServiceAccount and the kubelet's own
    environment. They are never caller-supplied, and the identity is the same
    read-only get/list/watch ServiceAccount either way — this makes an existing
    credential usable, it does not add one.
    """
    host = os.getenv("KUBERNETES_SERVICE_HOST", "")
    port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
    if not host or not os.path.exists(SA_TOKEN):
        raise ExecutorError(
            "in-cluster mode requested but this process is not running in a "
            "cluster: no KUBERNETES_SERVICE_HOST or no projected ServiceAccount "
            "token. Set the connection to a named kubeconfig context instead."
        )
    try:
        token = Path(SA_TOKEN).read_text().strip()
    except OSError as exc:
        raise ExecutorError(f"cannot read the ServiceAccount token: {exc}") from exc
    return [
        f"--server=https://{host}:{port}",
        f"--certificate-authority={SA_CA}",
        f"--token={token}",
    ]

#: Hard ceiling on --tail, applied here as well as in the registry ParamSpec.
MAX_TAIL_LINES = 1000

#: Hard ceiling on --since, in seconds (6h).
MAX_SINCE_SECONDS = 6 * 3600

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _duration_seconds(value: str) -> int:
    unit = value[-1]
    if unit not in _DURATION_UNITS or not value[:-1].isdigit():
        raise ExecutorError(f"refused: not a duration: {value!r}")
    return int(value[:-1]) * _DURATION_UNITS[unit]


class K8sExecutor(Executor):
    kind = "kubectl"

    def __init__(self, kubectl: str | None = None) -> None:
        self._kubectl = kubectl or shutil.which("kubectl") or "kubectl"

    # -- argv construction --------------------------------------------------

    @staticmethod
    def _check_value(name: str, value: Any) -> str:
        text = str(value)
        if not _ARG_RE.match(text):
            raise ExecutorError(
                f"refused: param '{name}' value {text!r} is not a valid Kubernetes "
                f"object name"
            )
        return text

    @classmethod
    def build_argv(
        cls, entry: RegistryEntry, params: dict[str, Any], context: str
    ) -> list[str]:
        """Build the full argv list. Returns a list — never a string."""
        if entry.kind != "kubectl" or not entry.argv:
            raise ExecutorError(f"{entry.name}: not a kubectl entry")

        verb = entry.argv[0]
        if verb not in VERB_ALLOWLIST:
            raise ExecutorError(
                f"refused kubectl verb '{verb}': not in the read-only allowlist "
                f"{sorted(VERB_ALLOWLIST)}"
            )

        rendered: list[str] = []
        for element in entry.argv:
            slots = PLACEHOLDER_RE.findall(element)
            if not slots:
                rendered.append(element)
                continue
            if any(params.get(slot) is None for slot in slots):
                # Optional slot not supplied: drop the whole argv element, and
                # its immediately preceding flag if that flag is now dangling.
                if rendered and rendered[-1].startswith("-") and "=" not in rendered[-1]:
                    rendered.pop()
                continue
            value = PLACEHOLDER_RE.sub(
                lambda m: cls._check_value(m.group(1), params[m.group(1)]), element
            )
            rendered.append(value)

        cls._enforce_caps(rendered)

        # The context comes from operator-supplied env, never from a caller, so
        # it is not name-shaped (EKS contexts are ARNs). Only guard the one
        # thing that would change kubectl's parse: a leading dash.
        if context.startswith("-"):
            raise ExecutorError("no usable kubectl context resolved for this connection")

        prefix: list[str] = []
        if context == IN_CLUSTER:
            prefix = in_cluster_flags()
        elif context == EKS_DIRECT:
            prefix = eks_direct_flags()
        elif context:
            prefix = ["--context", context]
        else:
            raise ExecutorError("no usable kubectl context resolved for this connection")
        # IN_CLUSTER omits --context entirely. Running inside the cluster there is
        # no kubeconfig and no named context: kubectl authenticates with the
        # pod's own ServiceAccount. Passing a context here would fail outright,
        # which would leave the tool unable to query the cluster it lives in.
        # This does not widen anything — the in-cluster identity is the same
        # read-only get/list/watch ServiceAccount.

        return [
            *prefix,
            "--request-timeout",
            f"{entry.timeout_s}s",
            *rendered,
        ]

    @staticmethod
    def _enforce_caps(argv: list[str]) -> None:
        """Re-apply the log caps in code. The registry sets them too; this is
        the layer that holds if the registry is edited badly."""
        for element in argv:
            if element.startswith("--tail="):
                raw = element.split("=", 1)[1]
                if not raw.lstrip("-").isdigit() or int(raw) < 1:
                    raise ExecutorError(f"refused: invalid --tail value {raw!r}")
                if int(raw) > MAX_TAIL_LINES:
                    raise ExecutorError(
                        f"refused: --tail {raw} exceeds cap of {MAX_TAIL_LINES}"
                    )
            elif element.startswith("--since="):
                seconds = _duration_seconds(element.split("=", 1)[1])
                if seconds > MAX_SINCE_SECONDS:
                    raise ExecutorError(
                        f"refused: --since exceeds cap of {MAX_SINCE_SECONDS}s"
                    )
            elif element in ("-f", "--follow", "--watch", "-w"):
                raise ExecutorError("refused: streaming/follow is not permitted")

    # -- run ----------------------------------------------------------------

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        try:
            conn = config.K8S_CONNECTIONS[target]
        except KeyError:
            raise ExecutorError(f"unknown k8s connection: {target}") from None

        namespace = params.get("namespace")
        if namespace is not None and namespace not in conn.namespaces:
            raise ExecutorError(
                f"refused: namespace '{namespace}' is not reachable on {target} "
                f"(allowed: {list(conn.namespaces)})"
            )

        argv = self.build_argv(entry, params, conn.context)

        started = self._timed()
        try:
            env = dict(os.environ)
            if conn.context and conn.context != IN_CLUSTER:
                env["KUBECONFIG"] = KUBECONFIG_PATH
            else:
                env.pop("KUBECONFIG", None)
            proc = await asyncio.create_subprocess_exec(
                self._kubectl,
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=entry.timeout_s + 5
                )
            except TimeoutError:
                proc.kill()
                raise ExecutorError(
                    f"{entry.name}: kubectl timed out after {entry.timeout_s}s"
                ) from None
        except ExecutorError:
            raise
        except OSError as exc:
            raise ExecutorError(f"{entry.name}: could not run kubectl: {exc}") from exc

        duration_ms = int((self._timed() - started) * 1000)
        text = stdout.decode(errors="replace")[:MAX_OUTPUT_BYTES]
        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[:4000].strip()
            raise ExecutorError(
                f"{entry.name}: kubectl exited {proc.returncode} on {target}: {err}"
            )

        result = ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            text=text,
            duration_ms=duration_ms,
        )
        result.cap_output()
        return result
