"""EKS bearer tokens: a presigned STS URL, not a token EKS issues.

The properties asserted here are the ones that fail opaquely if wrong — a bad
signature and a missing cluster binding both surface as a flat 401 from the API
server, with nothing to indicate which of the two it was.
"""

from __future__ import annotations

import base64
import datetime as dt
import urllib.parse

import pytest

from app.executors.ekstoken import eks_token


def _decode(token: str) -> str:
    assert token.startswith("k8s-aws-v1.")
    raw = token[len("k8s-aws-v1.") :]
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()


FIXED = dt.datetime(2026, 8, 19, 12, 0, 0, tzinfo=dt.UTC)


def _token(**kw) -> str:
    args = {
        "cluster_name": "example-eks-cluster",
        "region": "us-east-1",
        "access_key": "AKIAEXAMPLE",
        "secret_key": "secret",  # noqa: S106 - test fixture
        "session_token": "sess",  # noqa: S106 - test fixture
        "now": FIXED,
    }
    args.update(kw)
    return eks_token(**args)


def test_the_token_is_a_presigned_sts_get_caller_identity_url() -> None:
    url = _decode(_token())
    assert url.startswith("https://sts.us-east-1.amazonaws.com/?")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["Action"] == ["GetCallerIdentity"]
    assert q["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert q["X-Amz-Signature"]


def test_the_cluster_name_is_a_SIGNED_header() -> None:
    """This is what binds a token to ONE cluster. Without it in SignedHeaders a
    token minted for one cluster is replayable against another in the account.
    """
    url = _decode(_token())
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["X-Amz-SignedHeaders"] == ["host;x-k8s-aws-id"]


def test_a_different_cluster_produces_a_different_signature() -> None:
    a = urllib.parse.parse_qs(urllib.parse.urlparse(_decode(_token())).query)
    b = urllib.parse.parse_qs(
        urllib.parse.urlparse(_decode(_token(cluster_name="other-cluster"))).query
    )
    assert a["X-Amz-Signature"] != b["X-Amz-Signature"], (
        "the cluster name must affect the signature, or the binding is cosmetic"
    )


def test_the_session_token_is_carried() -> None:
    """Credentials here always come from AssumeRole, so omitting it 403s."""
    url = _decode(_token())
    assert "X-Amz-Security-Token=sess" in url


def test_no_padding_in_the_encoding() -> None:
    """The API server rejects '=' in the token."""
    assert "=" not in _token().split(".", 1)[1]


def test_the_url_expires_quickly() -> None:
    url = _decode(_token())
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert int(q["X-Amz-Expires"][0]) <= 900, "EKS caps presigned tokens at 15 min"
    assert int(q["X-Amz-Expires"][0]) <= 120, "and a leaked token should die fast"


def test_a_missing_cluster_name_is_refused_rather_than_signed_blank() -> None:
    with pytest.raises(ValueError, match="cluster_name"):
        _token(cluster_name="")


def test_the_signature_is_deterministic_for_fixed_inputs() -> None:
    assert _token() == _token()
