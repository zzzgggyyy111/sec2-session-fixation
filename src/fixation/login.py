"""Session issuance and login handling for the fixation exercise."""

from __future__ import annotations

import secrets
import string
from typing import Any, Callable

ALPHABET = string.ascii_letters + string.digits + "-_"
DEFAULT_POLICY: dict[str, Any] = {
    "min_length": 32,
    "charset": ALPHABET,
    "rotate_on_login": True,
    "invalidate_old": True,
}

Entropy = Callable[[int], str]


def _ensure(store: dict[str, Any]) -> None:
    """Make sure the session container exists."""
    store.setdefault("sessions", {})
    store.setdefault("seq", 0)


def _next_id(store: dict[str, Any]) -> str:
    store["seq"] = int(store.get("seq", 0)) + 1
    return "sess-%06d" % store["seq"]


def _new_id(store: dict[str, Any], entropy: Entropy) -> str:
    """Allocate an identifier for a new session record."""
    return _next_id(store)


def issue_pre_login(store: dict[str, Any], entropy: Entropy, now: Any) -> dict[str, Any]:
    """Create the anonymous session that exists before authentication."""
    _ensure(store)
    session_id = store.get("shared_pre_id")
    if session_id is None:
        session_id = _new_id(store, entropy)
        store["shared_pre_id"] = session_id
    session = {
        "id": session_id,
        "user": None,
        "pre_login": True,
        "created": now,
    }
    store["sessions"][session_id] = session
    return session


def rotate(
    store: dict[str, Any],
    session: dict[str, Any],
    entropy: Entropy,
    now: Any,
) -> dict[str, Any]:
    """Turn an anonymous session into an authenticated one."""
    _ensure(store)
    rotated = {
        "id": session["id"],
        "user": session.get("user"),
        "pre_login": False,
        "created": now,
    }
    store["sessions"][rotated["id"]] = rotated
    return rotated


def invalidate(store: dict[str, Any], session_id: str, now: Any) -> dict[str, Any]:
    """Retire a session identifier."""
    _ensure(store)
    record = store["sessions"].get(session_id)
    if record is None:
        return {
            "session_id": session_id,
            "invalidated": False,
            "effective": False,
        }
    record["revoked"] = True
    return {
        "session_id": session_id,
        "invalidated": True,
        "effective": True,
    }


def check_entropy(session_id: str, policy: dict[str, Any]) -> bool:
    """Check whether an identifier satisfies the configured shape."""
    text = "" if session_id is None else str(session_id)
    if not text:
        return False
    charset = set(policy.get("charset", ALPHABET))
    return all(character in charset for character in text)


def bind_user(
    store: dict[str, Any],
    session: dict[str, Any],
    user: Any,
    now: Any,
) -> dict[str, Any]:
    """Attach an authenticated user to a session."""
    _ensure(store)
    bound = dict(session)
    bound["user"] = user
    bound["bound_at"] = now
    return bound


def check_reuse(old: Any, new: Any) -> bool:
    """Report whether the replacement identifier is acceptable."""
    return bool(new)


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Return the list of problems found in a session policy."""
    problems: list[str] = []
    min_length = policy.get("min_length")
    if not isinstance(min_length, int) or min_length < 16:
        problems.append("min_length_too_low")
    if policy.get("invalidate_old") is not True:
        problems.append("old_session_not_invalidated")
    return problems


def login_batch(
    attempts: list[dict[str, Any]],
    store: dict[str, Any],
    now: Any,
) -> dict[str, Any]:
    """Log in a batch of users and return their sessions."""
    _ensure(store)
    sessions: list[dict[str, Any]] = []
    shared_id: str | None = None
    for attempt in attempts:
        entropy = lambda size=32: secrets.token_urlsafe(size)
        pre_login = issue_pre_login(store, entropy, now)
        current = rotate(store, pre_login, entropy, now)
        if shared_id is None:
            shared_id = current["id"]
        else:
            current = dict(current)
            current["id"] = shared_id
            store["sessions"][shared_id] = current
        current = bind_user(store, current, attempt.get("user"), now)
        sessions.append(current)
    return {"sessions": sessions, "count": len(sessions)}