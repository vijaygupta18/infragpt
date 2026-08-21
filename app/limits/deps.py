"""FastAPI dependencies for rate limits and token budgets.

Attach both to ``/ask``::

    @router.post("/ask")
    async def ask(
        principal: Annotated[Principal, Depends(check_token_budget)],
        _rate: Annotated[Principal, Depends(enforce_question_rate)],
        ...
    ) -> AskResponse: ...

Ordering note: ``enforce_question_rate`` **consumes** quota, so it should run
after the cheap checks that might reject the request for another reason. Both
dependencies chain off ``current_user``, so an unauthenticated or unactivated
caller is rejected before either limit is touched — an anonymous request can
never burn a real user's allowance.

Responses use 429 with a ``Retry-After`` header so ``infractl`` can back off
without parsing prose.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.auth.deps import Principal, current_user
from app.limits.service import Limits, get_limits
from app.storage import Storage, get_storage


def _limits_dep(storage: Annotated[Storage, Depends(get_storage)]) -> Limits:
    return get_limits(storage.db)


async def enforce_question_rate(
    principal: Annotated[Principal, Depends(current_user)],
    limits: Annotated[Limits, Depends(_limits_dep)],
) -> Principal:
    """Admit one question, consuming a unit of the hourly allowance.

    Consuming here (rather than after the answer) is deliberate: an expensive
    question that times out still cost the infrastructure the reads it made.
    """
    verdict = limits.consume_question(principal.user.id)
    if not verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=verdict.message(),
            headers={"Retry-After": str(verdict.retry_after_s)},
        )
    return principal


async def check_token_budget(
    principal: Annotated[Principal, Depends(current_user)],
    limits: Annotated[Limits, Depends(_limits_dep)],
) -> Principal:
    """Refuse if the caller has spent their day's tokens.

    Non-consuming: spend is recorded after the answer, by ``record_question_tokens``,
    once the real counts are known.
    """
    verdict = limits.check_tokens(principal.user.id)
    if not verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=verdict.message(),
            headers={"Retry-After": "3600"},
        )
    return principal


async def enforce_call_rate(
    principal: Annotated[Principal, Depends(current_user)],
    limits: Annotated[Limits, Depends(_limits_dep)],
) -> Principal:
    """For the direct ``infractl call`` path, which bypasses the LLM but not the
    infrastructure it reads."""
    verdict = limits.consume_call(principal.user.id)
    if not verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=verdict.message(),
            headers={"Retry-After": str(verdict.retry_after_s)},
        )
    return principal


def record_question_tokens(
    user_id: int, tokens_in: int, tokens_out: int, *, db: object | None = None
) -> None:
    """Record a finished question's token spend. Call once per answered question,
    including answers that ended in "I can't do that" — those cost tokens too."""
    limits = get_limits(db)  # type: ignore[arg-type]
    limits.record_tokens(user_id, tokens_in, tokens_out)


__all__ = [
    "check_token_budget",
    "enforce_call_rate",
    "enforce_question_rate",
    "record_question_tokens",
]
