#!/usr/bin/env bash
# View and verify Merkle audit log
set -euo pipefail

LAST="10" AGENT="" VERIFY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --last)   LAST="$2"; shift 2;;
    --agent)  AGENT="$2"; shift 2;;
    --verify) VERIFY="true"; shift;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

python3 -c "
import json
try:
    from agentmesh.governance.audit import AuditLog
    audit_log = AuditLog()
    agent_filter = '$AGENT' or None
    if agent_filter:
        entries = audit_log.get_entries_for_agent(agent_did=agent_filter, limit=int('$LAST'))
    else:
        entries = audit_log.query(limit=int('$LAST'))
    if '$VERIFY' == 'true':
        valid, error = audit_log.verify_integrity()
        print(json.dumps({'integrity': 'valid' if valid else 'TAMPERED', 'error': error, 'entries': len(entries)}, indent=2))
    else:
        print(json.dumps([e.to_dict() for e in entries], indent=2))
except ImportError:
    result = {
        'entries': [],
        'note': 'Install agentmesh for audit logging: pip install agentmesh'
    }
    print(json.dumps(result, indent=2))
"
