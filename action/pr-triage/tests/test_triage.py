import os
import sys
import json
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from triage import check_account_shape, check_cross_repo_spray, check_credential_claims, parse_watchlist

def test_parse_watchlist_valid():
    assert parse_watchlist('["actor1", "actor2"]') == ["actor1", "actor2"]

def test_parse_watchlist_invalid():
    assert parse_watchlist('{"not": "a list"}') == []
    assert parse_watchlist('invalid json') == []

def test_check_account_shape_suspicious():
    user = MagicMock()
    # Mock datetime is tricky, we'll just mock the attributes so they trigger the logic
    from datetime import datetime, timedelta, timezone
    user.created_at = datetime.now(timezone.utc) - timedelta(days=2) # 2 days old
    user.followers = 1
    user.following = 100
    user.public_repos = 0
    
    result = check_account_shape(user)
    assert result["suspicious_shape"] is True
    assert result["age_days"] == 2

def test_check_cross_repo_spray_detected():
    gh = MagicMock()
    mock_issue1 = MagicMock()
    mock_issue1.repository.full_name = "test/repo1"
    
    mock_issue2 = MagicMock()
    mock_issue2.repository.full_name = "test/repo2"
    
    gh.search_issues.return_value = [mock_issue1, mock_issue2]
    
    result = check_cross_repo_spray(gh, "testuser", threshold=2, monitor_repos=["test/repo1", "test/repo2"])
    assert result["spray_detected"] is True
    assert result["count"] == 2

def test_check_credential_claims_found():
    gh = MagicMock()
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_pr.state = "merged"
    mock_pr.merged = True
    
    gh.get_repo.return_value = mock_repo
    mock_repo.get_pull.return_value = mock_pr
    
    body = "Look at my work in https://github.com/microsoft/agent-governance-toolkit/pull/1485"
    result = check_credential_claims(gh, body)
    
    assert result["claims_found"] is True
    assert len(result["urls"]) == 1
    gh.get_repo.assert_called_with("microsoft/agent-governance-toolkit")
    mock_repo.get_pull.assert_called_with(1485)
