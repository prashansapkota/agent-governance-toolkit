import os
import json
import sys
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Union, Any

from github import Github, GithubException
from github.NamedUser import NamedUser
from github.Repository import Repository
from github.Issue import Issue
from github.PullRequest import PullRequest

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def load_event_data() -> Dict[str, Any]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        return {}
    try:
        with open(event_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse GITHUB_EVENT_PATH JSON: %s", e)
        return {}

def check_account_shape(user: NamedUser) -> Dict[str, Union[int, bool]]:
    """Check account age and follower ratio"""
    try:
        # Use timezone-aware UTC datetime
        age_days = (datetime.now(timezone.utc) - user.created_at.replace(tzinfo=timezone.utc)).days
        ratio = user.followers / max(1, user.following)
        suspicious_shape = age_days < 30 or (user.following > 50 and ratio < 0.1)
        return {
            "age_days": age_days,
            "followers": user.followers,
            "following": user.following,
            "public_repos": user.public_repos,
            "suspicious_shape": suspicious_shape
        }
    except Exception as e:
        logger.error("Error checking account shape: %s", e)
        return {"suspicious_shape": False}

def check_cross_repo_spray(gh: Github, username: str, threshold: int, monitor_repos: List[str]) -> Dict[str, Union[bool, int, List[str]]]:
    """Check if the user has filed multiple similar issues in monitored repos recently."""
    if not monitor_repos:
        return {"spray_detected": False, "count": 0, "repos": []}
    
    seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%d')
    query = f"author:{username} type:issue created:>{seven_days_ago}"
    
    try:
        issues = gh.search_issues(query=query)
        repo_matches = set()
        total_count = 0
        
        for issue in issues[:50]: # Limit pagination to avoid rate limits
            repo_name = issue.repository.full_name
            if repo_name in monitor_repos:
                repo_matches.add(repo_name)
                total_count += 1
                
        spray_detected = total_count >= threshold
        return {
            "spray_detected": spray_detected,
            "count": total_count,
            "repos": list(repo_matches)
        }
    except GithubException as e:
        logger.error("GitHub API error during spray check: %s", e)
        return {"spray_detected": False, "count": 0, "repos": []}

def check_credential_claims(gh: Github, body: str) -> Dict[str, Union[bool, List[str]]]:
    """Check if the body references PRs in other repositories and verifies their existence."""
    if not body:
        return {"claims_found": False, "urls": []}
    
    # Strict regex for PR URLs
    pr_url_pattern = re.compile(r'https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(\d+)')
    matches = pr_url_pattern.findall(body)
    
    verified_urls = []
    
    for repo_full_name, pr_number_str in matches:
        try:
            pr_number = int(pr_number_str)
            repo = gh.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Record the claim if the PR exists
            url = f"https://github.com/{repo_full_name}/pull/{pr_number}"
            verified_urls.append(url)
            logger.info("Verified credential claim PR: %s (State: %s, Merged: %s)", url, pr.state, pr.merged)
            
        except GithubException as e:
            logger.warning("Could not verify PR claim %s#%s: %s", repo_full_name, pr_number_str, e.data.get('message', 'Unknown error'))
        except Exception as e:
            logger.error("Unexpected error parsing PR claim %s#%s: %s", repo_full_name, pr_number_str, e)
            
    return {
        "claims_found": len(verified_urls) > 0,
        "urls": verified_urls
    }

def parse_watchlist(raw_input: str) -> List[str]:
    """Safely parse the watchlist JSON."""
    if not raw_input or raw_input.strip() == "":
        return []
    try:
        parsed = json.loads(raw_input)
        if isinstance(parsed, list) and all(isinstance(i, str) for i in parsed):
            return parsed
        logger.warning("Watchlist JSON is not a list of strings. Falling back to empty list.")
    except json.JSONDecodeError as e:
        logger.error("Failed to parse watchlist JSON: %s. Falling back to empty list.", e)
    return []

def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("GITHUB_TOKEN is required.")
        sys.exit(1)
        
    gh = Github(token)
    
    # 0. Validate Token Scope implicitly by fetching current user
    try:
        current_user = gh.get_user().login
        logger.info("Authenticated as: %s", current_user)
    except GithubException as e:
        logger.error("Failed to authenticate with provided GITHUB_TOKEN: %s", e)
        sys.exit(1)
    
    # Parse inputs
    try:
        spray_threshold = int(os.environ.get("SPRAY_THRESHOLD", "3"))
    except ValueError:
        logger.warning("Invalid SPRAY_THRESHOLD. Using default of 3.")
        spray_threshold = 3
        
    check_spray = os.environ.get("CHECK_SPRAY", "true").lower() == "true"
    check_credentials = os.environ.get("CHECK_CREDENTIALS", "true").lower() == "true"
    
    monitor_repos_raw = os.environ.get("MONITOR_REPOS", "")
    monitor_repos = [r.strip() for r in monitor_repos_raw.split('\n') if r.strip()]
    
    watchlist = parse_watchlist(os.environ.get("WATCHLIST", "[]"))
        
    event_data = load_event_data()
    if not event_data:
        # Fallback for local testing or manual trigger
        username = os.environ.get("TEST_USERNAME", "ghost")
        body = os.environ.get("TEST_BODY", "")
    else:
        if "pull_request" in event_data:
            item = event_data["pull_request"]
        elif "issue" in event_data:
            item = event_data["issue"]
        else:
            logger.info("Unsupported event type")
            sys.exit(0)
            
        username = item.get("user", {}).get("login", "ghost")
        body = item.get("body", "")

    logger.info("Analyzing user: %s", username)
    try:
        user = gh.get_user(username)
    except GithubException as e:
        logger.error("Failed to fetch user %s: %s", username, e)
        sys.exit(1)
    
    # 1. Account Shape
    shape = check_account_shape(user)
    
    # 2. Watchlist
    in_watchlist = username in watchlist
    
    # 3. Spray Check
    spray = check_cross_repo_spray(gh, username, spray_threshold, monitor_repos) if check_spray else {"spray_detected": False}
    
    # 4. Credential Claims
    claims = check_credential_claims(gh, body) if check_credentials else {"claims_found": False}
    
    # Calculate Risk
    risk_score = 0
    if shape.get("suspicious_shape"): risk_score += 1
    if in_watchlist: risk_score += 3
    if spray.get("spray_detected"): risk_score += 2
    if claims.get("claims_found"): risk_score += 1
    
    risk_level = "LOW"
    if risk_score >= 3:
        risk_level = "HIGH"
    elif risk_score >= 1:
        risk_level = "MEDIUM"
        
    findings = {
        "user": username,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "account_shape": shape,
        "in_watchlist": in_watchlist,
        "spray_analysis": spray,
        "credential_claims": claims
    }
    
    logger.info("Findings: %s", json.dumps(findings, indent=2))
    
    # Write to GitHub Actions outputs
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        try:
            with open(output_file, "a") as f:
                f.write(f"risk-level={risk_level}\n")
                f.write(f"spray-detected={str(spray.get('spray_detected', False)).lower()}\n")
                f.write("findings<<EOF\n")
                f.write(json.dumps(findings))
                f.write("\nEOF\n")
        except Exception as e:
            logger.error("Failed to write to GITHUB_OUTPUT: %s", e)
            
    # Post comment if risk is MEDIUM or HIGH and we're running in GitHub Actions
    if risk_level in ["MEDIUM", "HIGH"] and event_data:
        repo_name = os.environ.get("GITHUB_REPOSITORY")
        if not repo_name:
            return
            
        try:
            repo = gh.get_repo(repo_name)
            issue_number = event_data.get("pull_request", {}).get("number") or event_data.get("issue", {}).get("number")
            
            if issue_number:
                issue = repo.get_issue(number=issue_number)
                
                comment_body = f"⚠️ **PR Triage Action** ⚠️\n\n"
                comment_body += f"Detected **{risk_level}** risk profile for contributor `@'{username}'`.\n\n"
                
                if spray.get("spray_detected"):
                    comment_body += f"- **Spray Detected**: Author has filed similar issues across {spray.get('count')} monitored repositories.\n"
                if claims.get("claims_found"):
                    comment_body += f"- **Credential Claims**: Body cites PRs from other repositories to build credibility.\n"
                if shape.get("suspicious_shape"):
                    comment_body += f"- **Suspicious Account Shape**: Account is very new or has a low follower/following ratio.\n"
                    
                issue.create_comment(comment_body)
                issue.add_to_labels("needs-verification")
                logger.info("Successfully posted warning comment to %s#%s", repo_name, issue_number)
        except GithubException as e:
            logger.error("Failed to post comment or label to issue: %s", e)

if __name__ == "__main__":
    main()
