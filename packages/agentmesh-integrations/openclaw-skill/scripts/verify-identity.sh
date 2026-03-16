#!/usr/bin/env bash
# Verify agent Ed25519 identity
set -euo pipefail

DID="" MESSAGE="" SIGNATURE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --did)       DID="$2"; shift 2;;
    --message)   MESSAGE="$2"; shift 2;;
    --signature) SIGNATURE="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

python3 -c "
import json
try:
    from agentmesh.identity import AgentIdentity, AgentDID, IdentityRegistry
    parsed = AgentDID.from_string('$DID')
    registry = IdentityRegistry()
    identity = registry.get(parsed)
    if identity is None:
        print(json.dumps({'did': '$DID', 'verified': False, 'error': 'DID not found in registry'}, indent=2))
    else:
        verified = identity.verify_signature(b'$MESSAGE', '$SIGNATURE')
        print(json.dumps({'did': '$DID', 'verified': verified}, indent=2))
except ImportError:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import base64
    print(json.dumps({
        'did': '$DID',
        'verified': False,
        'note': 'Install agentmesh for full verification: pip install agentmesh'
    }, indent=2))
"
