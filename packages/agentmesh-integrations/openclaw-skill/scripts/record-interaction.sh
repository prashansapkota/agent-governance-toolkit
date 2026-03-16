#!/usr/bin/env bash
# Record interaction outcome and update trust score
set -euo pipefail

AGENT="" OUTCOME="" SEVERITY="0.05"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)    AGENT="$2"; shift 2;;
    --outcome)  OUTCOME="$2"; shift 2;;
    --severity) SEVERITY="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

python3 -c "
import json, datetime
try:
    from agentmesh.services import RewardService
    service = RewardService()
    if '$OUTCOME' == 'success':
        service.record_task_success('$AGENT', task_id='openclaw-interaction')
    else:
        service.record_task_failure('$AGENT', reason='severity=$SEVERITY')
    score = service.get_score('$AGENT')
    print(json.dumps(score.to_dict() if hasattr(score, 'to_dict') else score, indent=2))
except ImportError:
    delta = 0.01 if '$OUTCOME' == 'success' else -float('$SEVERITY')
    result = {
        'agent': '$AGENT',
        'outcome': '$OUTCOME',
        'score_delta': delta,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'note': 'Install agentmesh for persistent scoring: pip install agentmesh'
    }
    print(json.dumps(result, indent=2))
"
