#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Verification script for the structural-authz-agentmesh adapter.

Runs a suite of self-contained checks — no test framework required.
Each check prints PASS or FAIL with a short description.

Usage:
    python scripts/verify.py
    python scripts/verify.py --verbose
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the package importable when run from the repo root or from this directory
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from structural_authz_agentmesh import (
    AgentProfile,
    AuthzGate,
    DelegationChain,
    DelegationLink,
    TrustArtifact,
    TrustGrade,
    TrustTracker,
    generate_keypair,
)

_results: list[tuple[str, bool, str]] = []
_verbose = False

def check(name: str):
    """Decorator — wrap a zero-arg function as a named check."""
    def decorator(fn):
        try:
            fn()
            _results.append((name, True, ""))
            if _verbose:
                print(f"  [PASS] {name}")
        except Exception as exc:
            _results.append((name, False, str(exc)))
            if _verbose:
                print(f"  [FAIL] {name}")
                traceback.print_exc()
        return fn
    return decorator

def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)

def _past(seconds: int = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)

def _crypto_available() -> bool:
    try:
        generate_keypair()
        return True
    except RuntimeError:
        return False

@check("TrustGrade: all 6 grades exist")
def _():
    expected = {"verified", "trusted", "provisional", "restricted", "untrusted", "revoked"}
    assert {g.value for g in TrustGrade} == expected

@check("TrustGrade: score ordering is monotone")
def _():
    ordered = [
        TrustGrade.REVOKED,
        TrustGrade.UNTRUSTED,
        TrustGrade.RESTRICTED,
        TrustGrade.PROVISIONAL,
        TrustGrade.TRUSTED,
        TrustGrade.VERIFIED,
    ]
    scores = [g.to_agt_score() for g in ordered]
    assert scores == sorted(scores), f"Scores not sorted: {scores}"

@check("TrustGrade: REVOKED maps to 0")
def _():
    assert TrustGrade.REVOKED.to_agt_score() == 0

@check("TrustGrade: VERIFIED maps to 950")
def _():
    assert TrustGrade.VERIFIED.to_agt_score() == 950

@check("TrustGrade: round-trip from string value")
def _():
    for g in TrustGrade:
        assert TrustGrade(g.value) is g

@check("TrustArtifact: canonical payload is valid JSON with required keys")
def _():
    artifact = TrustArtifact(
        did="did:authz:test",
        grade=TrustGrade.TRUSTED,
        scopes=["read", "write"],
        issued_at=datetime.now(timezone.utc),
        expires_at=_future(),
        issuer_public_key="AAAA",
        signature="BBBB",
    )
    data = json.loads(artifact.canonical_payload())
    assert {"did", "grade", "scopes", "expires_at"} <= data.keys()

@check("TrustArtifact: canonical payload sorts scopes deterministically")
def _():
    expiry = _future()
    base = dict(
        did="did:authz:test",
        issued_at=datetime.now(timezone.utc),
        expires_at=expiry,
        issuer_public_key="AAAA",
        signature="BBBB",
    )
    a1 = TrustArtifact(grade=TrustGrade.TRUSTED, scopes=["write", "read"], **base)
    a2 = TrustArtifact(grade=TrustGrade.TRUSTED, scopes=["read", "write"], **base)
    assert a1.canonical_payload() == a2.canonical_payload()

@check("TrustArtifact: expired detection")
def _():
    artifact = TrustArtifact(
        did="did:authz:test",
        grade=TrustGrade.TRUSTED,
        scopes=[],
        issued_at=_past(7200),
        expires_at=_past(1),
        issuer_public_key="AAAA",
        signature="BBBB",
    )
    assert artifact.is_expired()

@check("TrustArtifact: not-expired detection")
def _():
    artifact = TrustArtifact(
        did="did:authz:test",
        grade=TrustGrade.TRUSTED,
        scopes=[],
        issued_at=datetime.now(timezone.utc),
        expires_at=_future(),
        issuer_public_key="AAAA",
        signature="BBBB",
    )
    assert not artifact.is_expired()

@check("TrustArtifact: to_dict / from_dict round-trip")
def _():
    artifact = TrustArtifact(
        did="did:authz:bob",
        grade=TrustGrade.VERIFIED,
        scopes=["admin", "read"],
        issued_at=datetime.now(timezone.utc),
        expires_at=_future(),
        issuer_public_key="AAAA",
        signature="BBBB",
        issuer_id="test-authority",
        metadata={"region": "us-east"},
    )
    restored = TrustArtifact.from_dict(artifact.to_dict())
    assert restored.did == artifact.did
    assert restored.grade == artifact.grade
    assert restored.scopes == artifact.scopes
    assert restored.issuer_id == artifact.issuer_id
    assert restored.metadata == artifact.metadata

@check("TrustArtifact: Ed25519 sign and verify")
def _():
    if not _crypto_available():
        return  # silently skip, crypto-gated
    priv, pub = generate_keypair()
    artifact = TrustArtifact.sign(
        did="did:authz:alice",
        grade=TrustGrade.TRUSTED,
        scopes=["read"],
        expires_at=_future(),
        private_key_b64=priv,
        issuer_public_key_b64=pub,
        issuer_id="verify-script",
    )
    assert artifact.verify_signature()

@check("TrustArtifact: tampered payload fails verification")
def _():
    if not _crypto_available():
        return
    priv, pub = generate_keypair()
    artifact = TrustArtifact.sign(
        did="did:authz:alice",
        grade=TrustGrade.TRUSTED,
        scopes=["read"],
        expires_at=_future(),
        private_key_b64=priv,
        issuer_public_key_b64=pub,
    )
    artifact.scopes = ["admin"]  # tamper
    assert not artifact.verify_signature()

@check("TrustArtifact: signed round-trip preserves valid signature")
def _():
    if not _crypto_available():
        return
    priv, pub = generate_keypair()
    artifact = TrustArtifact.sign(
        did="did:authz:carol",
        grade=TrustGrade.VERIFIED,
        scopes=["read", "write"],
        expires_at=_future(),
        private_key_b64=priv,
        issuer_public_key_b64=pub,
    )
    restored = TrustArtifact.from_dict(artifact.to_dict())
    assert restored.verify_signature()

@check("AgentProfile: defaults")
def _():
    agent = AgentProfile(did="did:authz:agent", name="Agent")
    assert agent.trust_score == 500
    assert agent.is_active
    assert agent.status == "active"

@check("AgentProfile: has_capability")
def _():
    agent = AgentProfile(did="did:authz:agent", name="A", capabilities=["read", "exec"])
    assert agent.has_capability("read")
    assert not agent.has_capability("admin")

@check("AgentProfile: has_all_capabilities")
def _():
    agent = AgentProfile(did="did:authz:agent", name="A", capabilities=["read", "write", "exec"])
    assert agent.has_all_capabilities(["read", "write"])
    assert not agent.has_all_capabilities(["read", "admin"])

@check("AgentProfile: inactive statuses")
def _():
    for status in ("suspended", "revoked"):
        a = AgentProfile(did="did:authz:x", name="X", status=status)
        assert not a.is_active

@check("AgentProfile: to_dict")
def _():
    agent = AgentProfile(did="did:authz:agent", name="Agent", trust_score=800)
    d = agent.to_dict()
    assert d["trust_score"] == 800
    assert d["did"] == "did:authz:agent"

def _make_agent(**kwargs) -> AgentProfile:
    defaults = dict(did="did:authz:alice", name="Alice", capabilities=["read", "write"], trust_score=500)
    defaults.update(kwargs)
    return AgentProfile(**defaults)

def _make_artifact(**kwargs) -> TrustArtifact:
    defaults = dict(
        did="did:authz:alice",
        grade=TrustGrade.TRUSTED,
        scopes=["read", "write"],
        issued_at=datetime.now(timezone.utc),
        expires_at=_future(),
        issuer_public_key="AAAA",
        signature="BBBB",
    )
    defaults.update(kwargs)
    return TrustArtifact(**defaults)

def _gate(min_trust: int = 500) -> AuthzGate:
    return AuthzGate(min_trust_score=min_trust, verify_signatures=False)

@check("AuthzGate: allowed — TRUSTED grade with matching scopes")
def _():
    decision = _gate().evaluate(_make_agent(), "task", _make_artifact(), required_scopes=["read"])
    assert decision.allowed

@check("AuthzGate: denied — inactive agent")
def _():
    decision = _gate().evaluate(_make_agent(status="revoked"), "task", _make_artifact())
    assert not decision.allowed
    assert "revoked" in decision.reason

@check("AuthzGate: denied — DID mismatch")
def _():
    decision = _gate().evaluate(
        _make_agent(did="did:authz:alice"),
        "task",
        _make_artifact(did="did:authz:bob"),
    )
    assert not decision.allowed
    assert "does not match" in decision.reason

@check("AuthzGate: denied — expired artifact")
def _():
    decision = _gate().evaluate(_make_agent(), "task", _make_artifact(expires_at=_past()))
    assert not decision.allowed
    assert "expired" in decision.reason

@check("AuthzGate: denied — grade below threshold")
def _():
    decision = _gate(min_trust=600).evaluate(
        _make_agent(), "task", _make_artifact(grade=TrustGrade.RESTRICTED)
    )
    assert not decision.allowed
    assert "below minimum" in decision.reason

@check("AuthzGate: denied — missing required scope")
def _():
    decision = _gate().evaluate(
        _make_agent(), "task", _make_artifact(scopes=["read"]), required_scopes=["admin"]
    )
    assert not decision.allowed
    assert "lacks required scopes" in decision.reason

@check("AuthzGate: denied — REVOKED grade always blocked (even at min_trust=0)")
def _():
    decision = AuthzGate(min_trust_score=0, verify_signatures=False).evaluate(
        _make_agent(), "task", _make_artifact(grade=TrustGrade.REVOKED)
    )
    assert not decision.allowed

@check("AuthzGate: allowed — PROVISIONAL at default min_trust=500")
def _():
    decision = _gate(500).evaluate(
        _make_agent(), "task", _make_artifact(grade=TrustGrade.PROVISIONAL, scopes=["read"]),
        required_scopes=["read"],
    )
    assert decision.allowed

@check("AuthzGate: artifact_grade propagated to decision")
def _():
    decision = _gate().evaluate(_make_agent(), "task", _make_artifact(grade=TrustGrade.VERIFIED))
    assert decision.artifact_grade == TrustGrade.VERIFIED

def _link(delegator: str, delegatee: str, scopes: list[str], expires_at=None) -> DelegationLink:
    return DelegationLink(
        delegator_did=delegator,
        delegatee_did=delegatee,
        scopes=scopes,
        delegator_public_key="AAAA",
        signature="",
        expires_at=expires_at,
    )

@check("DelegationChain: empty chain validates")
def _():
    chain = DelegationChain("did:authz:root", ["read", "write"])
    ok, reason = chain.validate()
    assert ok, reason

@check("DelegationChain: empty chain missing required scope is denied")
def _():
    chain = DelegationChain("did:authz:root", ["read"])
    ok, _ = chain.validate(required_scopes=["admin"])
    assert not ok

@check("DelegationChain: effective scopes for root")
def _():
    chain = DelegationChain("did:authz:root", ["read", "write"])
    assert chain.effective_scopes_for("did:authz:root") == {"read", "write"}

@check("DelegationChain: effective scopes for unknown DID")
def _():
    chain = DelegationChain("did:authz:root", ["read"])
    assert chain.effective_scopes_for("did:authz:nobody") == set()

@check("DelegationChain: contiguity error")
def _():
    chain = DelegationChain("did:authz:root", ["read"])
    chain.add_link(_link("did:authz:OTHER", "did:authz:agent", ["read"]))
    ok, reason = chain.validate()
    assert not ok
    assert "expected delegator" in reason

@check("DelegationChain: circular delegation error")
def _():
    chain = DelegationChain("did:authz:root", ["read"])
    chain.add_link(_link("did:authz:root", "did:authz:root", ["read"]))
    ok, reason = chain.validate()
    assert not ok
    assert "circular" in reason

@check("DelegationChain: expired link error")
def _():
    chain = DelegationChain("did:authz:root", ["read"])
    chain.add_link(_link("did:authz:root", "did:authz:agent", ["read"], expires_at=_past()))
    ok, reason = chain.validate()
    assert not ok
    assert "expired" in reason

@check("DelegationChain: scope widening error")
def _():
    chain = DelegationChain("did:authz:root", ["read"])
    chain.add_link(_link("did:authz:root", "did:authz:agent", ["read", "admin"]))
    ok, reason = chain.validate(verify_signatures=False)
    assert not ok
    assert "exceed" in reason

@check("DelegationChain: two-hop scope narrowing via effective_scopes_for")
def _():
    chain = DelegationChain("did:authz:root", ["read", "write", "admin"])
    chain.add_link(_link("did:authz:root", "did:authz:middle", ["read", "write"]))
    chain.add_link(_link("did:authz:middle", "did:authz:leaf", ["read"]))
    assert chain.effective_scopes_for("did:authz:middle") == {"read", "write"}
    assert chain.effective_scopes_for("did:authz:leaf") == {"read"}

@check("DelegationChain: signed chain validates end-to-end (crypto)")
def _():
    if not _crypto_available():
        return
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed

    root_priv, root_pub = generate_keypair()
    root_priv_obj = _ed.Ed25519PrivateKey.from_private_bytes(base64.b64decode(root_priv))

    chain = DelegationChain("did:authz:root", ["read", "write"])
    link = DelegationLink(
        delegator_did="did:authz:root",
        delegatee_did="did:authz:agent",
        scopes=["read"],
        delegator_public_key=root_pub,
        signature="",
        expires_at=_future(),
    )
    sig = root_priv_obj.sign(link.canonical_payload().encode())
    link.signature = base64.b64encode(sig).decode("ascii")
    chain.add_link(link)

    ok, reason = chain.validate(required_scopes=["read"], verify_signatures=True)
    assert ok, reason

@check("TrustTracker: success reward applied")
def _():
    tracker = TrustTracker(success_reward=20)
    agent = AgentProfile(did="did:authz:a", name="A", trust_score=500)
    new_score = tracker.record_success(agent, "task")
    assert new_score == 520
    assert agent.trust_score == 520

@check("TrustTracker: failure penalty applied")
def _():
    tracker = TrustTracker(failure_penalty=100)
    agent = AgentProfile(did="did:authz:a", name="A", trust_score=500)
    new_score = tracker.record_failure(agent, "task", "timeout")
    assert new_score == 400
    assert agent.trust_score == 400

@check("TrustTracker: score clamped at max")
def _():
    tracker = TrustTracker(success_reward=100, max_score=1000)
    agent = AgentProfile(did="did:authz:a", name="A", trust_score=980)
    tracker.record_success(agent)
    assert agent.trust_score == 1000

@check("TrustTracker: score clamped at min")
def _():
    tracker = TrustTracker(failure_penalty=200, min_score=0)
    agent = AgentProfile(did="did:authz:a", name="A", trust_score=100)
    tracker.record_failure(agent)
    assert agent.trust_score == 0

@check("TrustTracker: history filtered by DID")
def _():
    tracker = TrustTracker()
    a = AgentProfile(did="did:authz:a", name="A", trust_score=500)
    b = AgentProfile(did="did:authz:b", name="B", trust_score=500)
    tracker.record_success(a)
    tracker.record_failure(b)
    history = tracker.get_history(did="did:authz:a")
    assert len(history) == 1
    assert history[0]["event"] == "success"

@check("TrustTracker: history record has required fields")
def _():
    tracker = TrustTracker()
    agent = AgentProfile(did="did:authz:a", name="A", trust_score=500)
    tracker.record_failure(agent, "bad task", "policy violation")
    record = tracker.get_history()[0]
    for field in ("did", "event", "old_score", "new_score", "task", "timestamp"):
        assert field in record, f"missing field: {field}"

def main() -> None:
    global _verbose
    parser = argparse.ArgumentParser(description="Verify structural-authz-agentmesh adapter")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print each check result")
    args = parser.parse_args()
    _verbose = args.verbose

    crypto = _crypto_available()
    print(f"\nstructural-authz-agentmesh — verification")
    print(f"Ed25519 crypto: {'available' if crypto else 'NOT available (crypto checks skipped)'}")
    print()

    passed = [r for r in _results if r[1]]
    failed = [r for r in _results if not r[1]]
    total = len(_results)

    if not _verbose:
        for name, ok, _ in _results:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {name}")

    print()
    print(f"Results: {len(passed)}/{total} passed", end="")
    if failed:
        print(f", {len(failed)} failed")
        print()
        for name, _, err in failed:
            print(f"  FAIL: {name}")
            print(f"        {err}")
        sys.exit(1)
    else:
        print(" — all checks passed.")

if __name__ == "__main__":
    main()
