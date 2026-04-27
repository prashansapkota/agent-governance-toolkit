# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Structural Authorization Gates — End-to-End Demo
=================================================
Demonstrates the full lifecycle:

  1. Generate Ed25519 key pairs for a trust authority and two agents.
  2. Issue signed TrustArtifacts for each agent.
  3. Evaluate task authorization through the AuthzGate.
  4. Build and validate a delegation scope chain (root → sub-agent).
  5. Track outcomes through TrustTracker.

Usage:
    pip install 'structural-authz-agentmesh[crypto]'
    python examples/demo.py

No external services required — all operations are local and in-memory.
"""

from __future__ import annotations

import base64
import sys
from datetime import datetime, timedelta, timezone

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
except ImportError:
    print("ERROR: Ed25519 support requires the cryptography package.")
    print("Install with: pip install 'structural-authz-agentmesh[crypto]'")
    sys.exit(1)

try:
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
except ImportError as exc:
    print(f"ERROR: {exc}")
    print("Install with: pip install 'structural-authz-agentmesh[crypto]'")
    sys.exit(1)

_SEPARATOR = "-" * 60

def _section(title: str) -> None:
    print(f"\n{_SEPARATOR}")
    print(f"  {title}")
    print(_SEPARATOR)

def _ok(label: str, value: object = "") -> None:
    suffix = f"  {value}" if value != "" else ""
    print(f"  [OK]  {label}{suffix}")

def _fail(label: str, reason: str = "") -> None:
    suffix = f"  — {reason}" if reason else ""
    print(f"  [DENY] {label}{suffix}")

def _future(hours: int = 1) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=hours)

def _sign_link(link: DelegationLink, private_key_b64: str) -> DelegationLink:
    priv_bytes = base64.b64decode(private_key_b64)
    priv_obj = _ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = priv_obj.sign(link.canonical_payload().encode("utf-8"))
    link.signature = base64.b64encode(sig).decode("ascii")
    return link

_section("Step 1: Generate Ed25519 key pairs")

authority_priv, authority_pub = generate_keypair()
agent_a_priv, agent_a_pub = generate_keypair()
_, agent_b_pub = generate_keypair()

_ok("Authority key pair generated")
_ok("Agent A key pair generated")
_ok("Agent B key pair generated")

_section("Step 2: Create agent profiles")

agent_a = AgentProfile(
    did="did:authz:agent-a",
    name="Data Analyst",
    capabilities=["read:data", "analyze:reports"],
    trust_score=700,
)

agent_b = AgentProfile(
    did="did:authz:agent-b",
    name="Sub-Analyst",
    capabilities=["read:data"],
    trust_score=500,
)

_ok(f"Agent A — {agent_a.name} ({agent_a.did})", f"score={agent_a.trust_score}")
_ok(f"Agent B — {agent_b.name} ({agent_b.did})", f"score={agent_b.trust_score}")

_section("Step 3: Issue signed TrustArtifacts")

artifact_a = TrustArtifact.sign(
    did=agent_a.did,
    grade=TrustGrade.TRUSTED,
    scopes=["read:data", "analyze:reports", "export:csv"],
    expires_at=_future(hours=8),
    private_key_b64=authority_priv,
    issuer_public_key_b64=authority_pub,
    issuer_id="demo-authority",
    metadata={"env": "demo", "region": "us-east"},
)

artifact_revoked = TrustArtifact.sign(
    did=agent_b.did,
    grade=TrustGrade.REVOKED,
    scopes=["read:data"],
    expires_at=_future(hours=1),
    private_key_b64=authority_priv,
    issuer_public_key_b64=authority_pub,
    issuer_id="demo-authority",
)

_ok(f"Artifact for Agent A — grade={artifact_a.grade.value}  AGT score={artifact_a.grade.to_agt_score()}")
_ok(f"Artifact for Agent B — grade={artifact_revoked.grade.value}  AGT score={artifact_revoked.grade.to_agt_score()}")
_ok(f"Signature valid (A): {artifact_a.verify_signature()}")
_ok(f"Signature valid (B/revoked): {artifact_revoked.verify_signature()}")

_section("Step 4: AuthzGate evaluation")

gate = AuthzGate(min_trust_score=500, verify_signatures=True)

# Should be allowed — TRUSTED grade (750) ≥ 500, scopes covered
decision = gate.evaluate(
    agent=agent_a,
    task="Generate quarterly report",
    artifact=artifact_a,
    required_scopes=["read:data", "analyze:reports"],
)
if decision.allowed:
    _ok(f"Agent A → '{decision.task}'", f"grade={decision.artifact_grade.value}")
else:
    _fail(f"Agent A → '{decision.task}'", decision.reason)

# Should be denied — REVOKED grade always blocks regardless of score threshold
decision_rev = gate.evaluate(
    agent=agent_b,
    task="Read dataset",
    artifact=artifact_revoked,
    required_scopes=["read:data"],
)
if decision_rev.allowed:
    _ok(f"Agent B → '{decision_rev.task}'")
else:
    _fail(f"Agent B → '{decision_rev.task}'", decision_rev.reason)

# Should be denied — scope not in artifact
decision_scope = gate.evaluate(
    agent=agent_a,
    task="Delete records",
    artifact=artifact_a,
    required_scopes=["delete:records"],
)
if decision_scope.allowed:
    _ok(f"Agent A → '{decision_scope.task}'")
else:
    _fail(f"Agent A → '{decision_scope.task}'", decision_scope.reason)

_section("Step 5: Delegation scope chain (Agent A → Agent B)")

link = DelegationLink(
    delegator_did="did:authz:agent-a",
    delegatee_did="did:authz:agent-b",
    scopes=["read:data"],
    delegator_public_key=agent_a_pub,
    signature="",
    expires_at=_future(hours=2),
)
link = _sign_link(link, agent_a_priv)

chain = DelegationChain(
    root_did="did:authz:agent-a",
    root_scopes=["read:data", "analyze:reports", "export:csv"],
)
chain.add_link(link)

valid, reason = chain.validate(required_scopes=["read:data"], verify_signatures=True)
if valid:
    _ok("Chain valid — Agent B holds 'read:data' via delegation")
else:
    _fail("Chain validation failed", reason)

effective = chain.effective_scopes_for("did:authz:agent-b")
_ok(f"Effective scopes for Agent B: {sorted(effective)}")

artifact_b = TrustArtifact.sign(
    did=agent_b.did,
    grade=TrustGrade.PROVISIONAL,
    scopes=["read:data"],
    expires_at=_future(hours=1),
    private_key_b64=authority_priv,
    issuer_public_key_b64=authority_pub,
    issuer_id="demo-authority",
)

decision_chain = gate.evaluate(
    agent=agent_b,
    task="Read delegated dataset",
    artifact=artifact_b,
    required_scopes=["read:data"],
    delegation_chain=chain,
)
if decision_chain.allowed:
    _ok(f"Agent B → '{decision_chain.task}' (via chain)", f"grade={decision_chain.artifact_grade.value}")
else:
    _fail(f"Agent B → '{decision_chain.task}'", decision_chain.reason)

_section("Step 6: TrustTracker — score updates")

tracker = TrustTracker(success_reward=10, failure_penalty=50)

print(f"  Agent A score before: {agent_a.trust_score}")
tracker.record_success(agent_a, task="Generate quarterly report")
_ok(f"After success (+10): {agent_a.trust_score}")

tracker.record_failure(agent_a, task="Delete records", reason="Unauthorized scope")
_ok(f"After failure  (-50): {agent_a.trust_score}")

history = tracker.get_history(did=agent_a.did)
_ok(f"History entries for Agent A: {len(history)}")

_section("Step 7: TrustArtifact serialization round-trip")

serialized = artifact_a.to_dict()
restored = TrustArtifact.from_dict(serialized)
assert restored.verify_signature(), "Signature must survive round-trip"
assert restored.grade == artifact_a.grade
assert restored.scopes == artifact_a.scopes
_ok("to_dict() → from_dict() round-trip preserves signature and fields")

_section("Summary")
print("  All demonstrations completed.")
print()
print("  Classes exercised:")
print("    TrustGrade      — 6-level external grade enum with AGT score mapping")
print("    TrustArtifact   — signed policy decision (Ed25519, canonical JSON)")
print("    DelegationLink  — single delegation hop with scope narrowing")
print("    DelegationChain — multi-hop validation (contiguity, cycles, expiry)")
print("    AgentProfile    — agent identity with capabilities and trust score")
print("    AuthzGate       — policy gate consuming artifacts and chains")
print("    TrustTracker    — score tracking with reward/penalty")
print()
