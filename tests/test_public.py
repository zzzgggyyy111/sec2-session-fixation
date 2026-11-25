"""Public contract tests for the fixation exercise."""

from __future__ import annotations

from fixation import (
    DEFAULT_POLICY,
    check_entropy,
    issue_pre_login,
    login_batch,
    rotate,
)


class FakeEntropy:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    def __call__(self, size: int) -> str:
        token = "tok%02d" % len(self.tokens) + "x" * max(int(size), 40)
        self.tokens.append(token)
        return token


def test_pre_login_sessions_are_distinct() -> None:
    store: dict = {}
    entropy = FakeEntropy()
    first = issue_pre_login(store, entropy, 0)
    second = issue_pre_login(store, entropy, 1)

    assert first["pre_login"] is True
    assert second["pre_login"] is True
    assert first["id"] != second["id"]
    assert len(store["sessions"]) == 2


def test_login_rotates_identifier() -> None:
    store: dict = {}
    entropy = FakeEntropy()
    pre_login = issue_pre_login(store, entropy, 0)

    authenticated = rotate(store, pre_login, entropy, 1)

    assert authenticated["id"] != pre_login["id"]
    assert authenticated["pre_login"] is False


def test_old_identifier_is_invalidated() -> None:
    store: dict = {}
    entropy = FakeEntropy()
    pre_login = issue_pre_login(store, entropy, 0)
    old_id = pre_login["id"]

    authenticated = rotate(store, pre_login, entropy, 1)

    assert old_id not in store["sessions"]
    assert authenticated["id"] in store["sessions"]


def test_identifier_length_is_enforced() -> None:
    assert check_entropy("a" * 31, DEFAULT_POLICY) is False
    assert check_entropy("a" * 32, DEFAULT_POLICY) is True
    assert check_entropy("short", DEFAULT_POLICY) is False


def test_batch_sessions_are_independent() -> None:
    store: dict = {}
    result = login_batch([{"user": "alice"}, {"user": "bob"}], store, 0)
    sessions = result["sessions"]

    assert result["count"] == 2
    assert len({session["id"] for session in sessions}) == 2
    assert {session["user"] for session in sessions} == {"alice", "bob"}