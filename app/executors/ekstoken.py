"""Mint an EKS bearer token from AWS credentials.

EKS does not issue tokens. It accepts a PRESIGNED STS `GetCallerIdentity` URL as
a bearer token: the API server calls that URL, AWS answers with the identity
that signed it, and the cluster maps that identity to Kubernetes permissions.
So "getting a token" is really "signing a URL that proves who we are".

The format is what `aws eks get-token` produces:

    k8s-aws-v1.<base64url(presigned URL, no padding)>

Two details that are easy to get wrong and fail opaquely:

* The signature must be a QUERY-STRING signature, not the header signature used
  everywhere else in awsapi.py — the API server receives only a URL.
* `x-k8s-aws-id: <cluster-name>` must be a SIGNED header. It is what binds the
  token to one cluster. Without it in `SignedHeaders`, a token minted for one
  cluster would be replayable against another in the same account.

Deliberately no boto3. The whole exchange is one signature and some string
formatting, and this container stays thin.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import urllib.parse

_ALGORITHM = "AWS4-HMAC-SHA256"
#: EKS accepts a presigned URL valid for at most 15 minutes; 60s is plenty for
#: an immediate call and keeps a leaked token near-worthless.
_EXPIRY_SECONDS = 60
_TOKEN_PREFIX = "k8s-aws-v1."  # noqa: S105 - a format marker, not a credential


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k = _sign(f"AWS4{secret}".encode(), date)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def eks_token(
    cluster_name: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str = "",
    now: dt.datetime | None = None,
) -> str:
    """Return a bearer token the EKS API server will accept.

    ``now`` is injectable so the signature can be asserted against a fixed
    timestamp in tests; production always passes None.
    """
    if not cluster_name:
        raise ValueError("cluster_name is required — it is a signed header")

    moment = now or dt.datetime.now(dt.UTC)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = moment.strftime("%Y%m%d")
    host = f"sts.{region}.amazonaws.com"
    scope = f"{date_stamp}/{region}/sts/aws4_request"

    # The cluster binding. Lower-cased because canonical headers are, and sorted
    # into SignedHeaders alphabetically: host, then x-k8s-aws-id.
    signed_headers = "host;x-k8s-aws-id"
    canonical_headers = f"host:{host}\nx-k8s-aws-id:{cluster_name}\n"

    query: dict[str, str] = {
        "Action": "GetCallerIdentity",
        "Version": "2011-06-15",
        "X-Amz-Algorithm": _ALGORITHM,
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(_EXPIRY_SECONDS),
        "X-Amz-SignedHeaders": signed_headers,
    }
    if session_token:
        # Required whenever the credentials came from AssumeRole — which they
        # always do here, since this deployment federates rather than storing
        # a key.
        query["X-Amz-Security-Token"] = session_token

    canonical_query = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in sorted(query.items())
    )

    # The SHA-256 of an EMPTY BODY, not the literal "UNSIGNED-PAYLOAD".
    #
    # Verified against `aws eks get-token` on 2026-08-19: the two produce
    # different signatures, and only this one is accepted. UNSIGNED-PAYLOAD is
    # what S3 presigning uses and what most write-ups describe, which is why
    # this is worth stating — the failure mode is a flat 401 from the API server
    # with nothing to say which half of the signature was wrong.
    canonical_request = "\n".join(
        (
            "GET",
            "/",
            canonical_query,
            canonical_headers,
            signed_headers,
            hashlib.sha256(b"").hexdigest(),
        )
    )
    to_sign = "\n".join(
        (
            _ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        )
    )
    signature = hmac.new(
        _signing_key(secret_key, date_stamp, region, "sts"),
        to_sign.encode(),
        hashlib.sha256,
    ).hexdigest()

    url = f"https://{host}/?{canonical_query}&X-Amz-Signature={signature}"
    # base64url WITHOUT padding — the API server rejects '=' characters.
    encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return f"{_TOKEN_PREFIX}{encoded}"
