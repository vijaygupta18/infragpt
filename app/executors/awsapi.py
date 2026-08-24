"""AWS control-plane executors — CloudWatch and ElastiCache, over signed REST.

Same reasoning as the GCP executors: no CLI in the container, no extra subprocess
surface, pinned API versions. SigV4 is signed here with stdlib hmac/hashlib
rather than pulling in boto3 — the signing is ~40 lines and avoids a large
dependency for what amounts to two GET-shaped calls.

Read-only by construction: only `Describe*` and `GetMetricStatistics` actions are
reachable, and the IAM role should carry `CloudWatchReadOnlyAccess` +
`AmazonElastiCacheReadOnlyAccess` and nothing more. As everywhere else in this
system, the credential is the real enforcement.

DEPLOYMENT NOTE: this reads static credentials from the environment. Under IRSA a
projected web-identity token must first be exchanged via STS
AssumeRoleWithWebIdentity; the deploy manifests use an ExternalSecret to supply
credentials directly instead, which keeps this module dependency-free.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import os
import urllib.parse
from typing import Any
from xml.etree import ElementTree

import httpx

from app import config
from app.executors.base import ExecResult, Executor, ExecutorError
from app.registry.schema import RegistryEntry

_ALGORITHM = "AWS4-HMAC-SHA256"


#: IRSA credentials, cached until shortly before expiry.
_irsa_cache: tuple[tuple[str, str, str], float] | None = None


def _irsa_creds() -> tuple[str, str, str] | None:
    """Exchange the projected web-identity token for temporary credentials.

    EKS mounts a short-lived OIDC token at AWS_WEB_IDENTITY_TOKEN_FILE and sets
    AWS_ROLE_ARN. AssumeRoleWithWebIdentity is itself unsigned — it is the call
    that bootstraps signing — so this needs no SigV4 and no boto3.

    The point of doing it this way: there is no long-lived AWS key anywhere.
    Nothing to rotate, nothing to leak from a Secret, and the credential expires
    on its own.
    """
    global _irsa_cache
    if _irsa_cache and _irsa_cache[1] > _dt.datetime.now(_dt.UTC).timestamp() + 60:
        return _irsa_cache[0]

    token_file = os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
    role_arn = os.getenv("AWS_ROLE_ARN", "")
    if not token_file or not role_arn:
        return None
    try:
        web_token = open(token_file).read().strip()  # noqa: SIM115, PTH123
    except OSError:
        return None

    params = urllib.parse.urlencode(
        {
            "Action": "AssumeRoleWithWebIdentity",
            "Version": "2011-06-15",
            "RoleArn": role_arn,
            "RoleSessionName": "infragpt",
            "WebIdentityToken": web_token,
        }
    )
    try:
        resp = httpx.post(
            "https://sts.amazonaws.com/",
            content=params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
    except httpx.HTTPError:
        return None
    if resp.status_code >= 400:
        return None
    rows = _findall(resp.text, "Credentials")
    if not rows:
        return None
    c = rows[0]
    creds = (
        c.get("AccessKeyId", ""),
        c.get("SecretAccessKey", ""),
        c.get("SessionToken", ""),
    )
    if not creds[0] or not creds[1]:
        return None
    # Refresh a minute early rather than parsing the ISO expiry precisely.
    _irsa_cache = (creds, _dt.datetime.now(_dt.UTC).timestamp() + 3000)
    return creds


def _creds() -> tuple[str, str, str]:
    """Static env credentials if present, else IRSA.

    Env first so local development works with `aws configure export-credentials`;
    in-cluster there are no static keys and IRSA supplies short-lived ones.
    """
    key = os.getenv("AWS_ACCESS_KEY_ID", "")
    secret = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    token = os.getenv("AWS_SESSION_TOKEN", "")
    if key and secret:
        return key, secret, token
    irsa = _irsa_creds()
    if irsa:
        return irsa
    raise ExecutorError(
        "No AWS credentials. In-cluster these come from IRSA — check the "
        "ServiceAccount annotation eks.amazonaws.com/role-arn. Locally, export "
        "them with `aws configure export-credentials --profile prod --format env`."
    )


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k = _sign(f"AWS4{secret}".encode(), date)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def aws_get_json(service: str, region: str, path: str, timeout_s: int = 15) -> dict:
    """Signed GET against a REST-style AWS API (EKS), returning parsed JSON.

    Separate from `_post`, which speaks the older form-encoded Query protocol
    used by CloudWatch and ElastiCache. EKS is a REST API, so the canonical
    request differs — GET, a real path, and an empty body.

    Synchronous on purpose: the one caller builds kubectl flags on a sync path,
    and threading async through it for a single cached lookup would be worse
    than a short blocking call.
    """
    import httpx

    host = f"{service}.{region}.amazonaws.com"
    access_key, secret, session_token = _creds()
    now = _dt.datetime.now(_dt.UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(b"").hexdigest()

    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed = "host;x-amz-date"
    if session_token:
        canonical_headers = (
            f"host:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{session_token}\n"
        )
        signed = "host;x-amz-date;x-amz-security-token"

    canonical_request = "\n".join(
        ("GET", path, "", canonical_headers, signed, payload_hash)
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        (
            _ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        )
    )
    signature = hmac.new(
        _signing_key(secret, date_stamp, region, service), to_sign.encode(), hashlib.sha256
    ).hexdigest()

    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "Authorization": (
            f"{_ALGORITHM} Credential={access_key}/{scope}, "
            f"SignedHeaders={signed}, Signature={signature}"
        ),
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    response = httpx.get(f"https://{host}{path}", headers=headers, timeout=timeout_s)
    if response.status_code >= 400:
        raise ExecutorError(
            f"aws {service} GET {path} returned HTTP {response.status_code}: "
            f"{response.text[:200]}"
        )
    return response.json()


#: Keepalive client shared by every AWS call — a client per call paid TCP+TLS
#: setup to amazonaws.com on each read.
_client: httpx.AsyncClient | None = None


def _shared_client() -> httpx.AsyncClient:
    global _client  # noqa: PLW0603
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
        )
    return _client


def _signed_headers(
    service: str, region: str, host: str, body: str
) -> dict[str, str]:
    """SigV4 for a POST form-encoded Query-protocol request."""
    access_key, secret, session_token = _creds()
    now = _dt.datetime.now(_dt.UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_headers = (
        f"content-type:application/x-www-form-urlencoded; charset=utf-8\n"
        f"host:{host}\nx-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"
    if session_token:
        canonical_headers += f"x-amz-security-token:{session_token}\n"
        signed_headers += ";x-amz-security-token"

    canonical_request = (
        f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    to_sign = (
        f"{_ALGORITHM}\n{amz_date}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    signature = hmac.new(
        _signing_key(secret, date_stamp, region, service), to_sign.encode(), hashlib.sha256
    ).hexdigest()

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "X-Amz-Date": amz_date,
        "Authorization": (
            f"{_ALGORITHM} Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


def _conn(target: str) -> config.AwsApiConnection:
    try:
        return config.AWS_CONNECTIONS[target]
    except KeyError:
        raise ExecutorError(f"unknown aws connection: {target}") from None


async def _post(service: str, region: str, params: dict[str, str], timeout_s: int) -> str:
    host = f"{service}.{region}.amazonaws.com"
    body = urllib.parse.urlencode(sorted(params.items()))
    headers = _signed_headers(service, region, host, body)
    try:
        resp = await _shared_client().post(
            f"https://{host}/", content=body, headers=headers, timeout=timeout_s
        )
    except httpx.HTTPError as exc:
        raise ExecutorError(f"AWS API unreachable: {exc}") from exc
    if resp.status_code == 403:
        raise ExecutorError(
            "AWS API returned 403 — the role lacks read permission for this "
            "resource, or the credentials expired. A permissions problem, not an outage."
        )
    if resp.status_code >= 400:
        raise ExecutorError(f"AWS API returned {resp.status_code}: {resp.text[:300]}")
    return resp.text


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _findall(xml: str, wanted: str) -> list[dict[str, str]]:
    """Collect every element named `wanted`, flattened to its leaf children."""
    root = ElementTree.fromstring(xml)  # noqa: S314 - AWS-signed response
    out: list[dict[str, str]] = []
    for el in root.iter():
        if _strip_ns(el.tag) != wanted:
            continue
        row: dict[str, str] = {}
        for child in el:
            if len(child) == 0 and child.text:
                row[_strip_ns(child.tag)] = child.text.strip()
        if row:
            out.append(row)
    return out


class AwsMetricExecutor(Executor):
    """CloudWatch GetMetricStatistics. Public endpoint — no VPC route needed."""

    kind = "awsmetric"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        started = self._timed()
        conn = _conn(target)
        if not entry.metric:
            raise ExecutorError(f"{entry.name}: entry declares no metric")

        window = str(params.get("window") or "30m")
        seconds = _window_seconds(window)
        end = _dt.datetime.now(_dt.UTC)
        start = end - _dt.timedelta(seconds=seconds)

        cluster = str(params.get("cluster") or "")
        query = {
            "Action": "GetMetricStatistics",
            "Version": "2010-08-01",
            "Namespace": entry.namespace or "AWS/ElastiCache",
            "MetricName": entry.metric,
            "StartTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "EndTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Period": str(max(60, min(seconds, 3600))),
            "Statistics.member.1": "Average",
            "Statistics.member.2": "Maximum",
        }
        if cluster:
            query["Dimensions.member.1.Name"] = "CacheClusterId"
            query["Dimensions.member.1.Value"] = cluster

        xml = await _post("monitoring", conn.region, query, entry.timeout_s)
        points = _findall(xml, "member")
        points.sort(key=lambda p: p.get("Timestamp", ""))
        rows = [
            {
                "cluster": cluster or "(all)",
                "timestamp": p.get("Timestamp"),
                "average": p.get("Average"),
                "maximum": p.get("Maximum"),
                "unit": p.get("Unit", "(unit not reported)"),
            }
            for p in points
            if "Average" in p or "Maximum" in p
        ]

        result = ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows[-entry.row_limit :],
            duration_ms=int((self._timed() - started) * 1000),
        )
        if not rows:
            result.text = (
                f"No datapoints for {entry.metric} on '{cluster or 'any cluster'}' "
                f"in the last {window}. This means no data, not zero."
            )
        return result


class AwsElastiCacheExecutor(Executor):
    """ElastiCache DescribeCacheClusters — inventory."""

    kind = "awselasticache"

    async def run(
        self, entry: RegistryEntry, params: dict[str, Any], target: str
    ) -> ExecResult:
        started = self._timed()
        conn = _conn(target)
        xml = await _post(
            "elasticache",
            conn.region,
            {"Action": "DescribeCacheClusters", "Version": "2015-02-02"},
            entry.timeout_s,
        )
        rows = [
            {
                "cluster": c.get("CacheClusterId"),
                "engine": c.get("Engine"),
                "version": c.get("EngineVersion"),
                "node_type": c.get("CacheNodeType"),
                "status": c.get("CacheClusterStatus"),
                "nodes": c.get("NumCacheNodes"),
            }
            for c in _findall(xml, "CacheCluster")
            if c.get("CacheClusterId")
        ]
        rows.sort(key=lambda r: str(r.get("cluster")))
        return ExecResult(
            ok=True,
            entry_name=entry.name,
            target=target,
            rows=rows[: entry.row_limit],
            duration_ms=int((self._timed() - started) * 1000),
        )


def _window_seconds(raw: str) -> int:
    from app.executors.gcpapi import _window_seconds as gcp_window

    return gcp_window(raw)
