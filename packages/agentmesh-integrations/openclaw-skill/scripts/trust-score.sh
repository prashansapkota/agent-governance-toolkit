#!/usr/bin/env bash
# Get agent trust score
set -euo pipefail

AGENT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent) AGENT="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

python3 -c "
import json
try:
    from agentmesh.services import RewardService
    service = RewardService()
    score = service.get_score('$AGENT')
    print(json.dumps(score.to_dict() if hasattr(score, 'to_dict') else score, indent=2))
except ImportError:
    # Standalone mode — return baseline trust info
    result = {
        'agent': '$AGENT',
        'trust_score': 0.5,
        'dimensions': {
            'policy_compliance': 0.5,
            'resource_efficiency': 0.5,
            'output_quality': 0.5,
            'security_posture': 0.5,
            'collaboration_health': 0.5
        },
        'status': 'baseline',
        'note': 'Install agentmesh for full trust scoring: pip install agentmesh'
    }
    print(json.dumps(result, indent=2))
"
