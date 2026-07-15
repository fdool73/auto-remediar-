#!/usr/bin/env python3
"""
gitlab_secret_remediation.py

Turns a TruffleHog Enterprise unified "secrets.csv" export into tracked
GitLab remediation work: one Merge Request per finding that's still
reachable on a branch, or one Issue per finding that only exists in
history/logs (dangling commit, pruned object, etc). Non-GitLab findings
(Slack, Confluence, Docker registries, package managers, ...) are
identified via the `source` column and reported separately rather than
mishandled as git repos.

WHY NOT AUTO-EDIT THE SECRET OUT OF THE FILE?
  This script deliberately does NOT try to rewrite the flagged line of
  code. Doing that safely requires knowing the correct replacement
  (which vault path, which CI variable name, whether the line is even
  syntactically simple) -- guessing wrong can break a build silently.
  Instead, each MR/Issue contains everything a human needs to fix it
  fast: exact repo/branch/file/line, commit link, detector type, and a
  remediation checklist. The MR *is* the tracked work item.

REQUIREMENTS
  pip install requests

ENV VARS (required)
  GITLAB_URL                   e.g. https://gitlab.example.com
  GITLAB_TOKEN                 personal/project access token, scope: api
                                (needs at least Developer on target repos,
                                Reporter+ to read user/member info)

ENV VARS (optional)
  GITLAB_FALLBACK_ASSIGNEE     GitLab username to assign when the original
                                committer can't be resolved / is inactive /
                                is no longer a project member. Falls back to
                                this if set; otherwise falls back to
                                --fallback-assignee CLI arg.

CSV SCHEMA
  This targets TruffleHog Enterprise's unified export, which pools findings
  from many connectors (GitLab, Slack, Confluence, Docker registries, package
  managers, etc) into one CSV, disambiguated by the `source` column. Expected
  headers (reconstructed from an actual export -- confirm with --inspect-csv,
  since exact spelling can vary by TruffleHog version):

    file_name, commit, url, channel_name, channel_identifier, timestamp,
    registry, region, layer_hash, image_hash, image_name, tag, bucket, issue,
    title, vcs_type, user_id, username, email, repository, build_number,
    build_step, account_name, package_name, release_name, workspace_id,
    workspace_name, snippet_id, page, space, version, org, pipeline, link,
    redacted, verified, source, id, secret_type, found_on, last_seen,
    date_rotated, triage_state, decoder_type, verification_error_type,
    verification_error_subtype, TruffleHog link

  Only rows where source == "GitLab" go through the branch/MR/issue flow.
  Everything else is counted and listed in the summary for manual routing
  (a Slack webhook leak needs a different remediation path than a git repo).

  `email` in this export is "Full Name <email@domain>", not a bare address --
  the script parses it. `url` already embeds the commit sha and line number
  (.../blob/<sha>/path#L123); there's no separate line-number column, so the
  script extracts it from there.

  Edit CANONICAL_COLUMNS below (or pass --column-map a.json file mapping
  canonical_name -> actual_header_in_your_csv) if your export differs.
  Run with --inspect-csv first to print your file's actual headers and the
  resolved mapping before doing anything else.

USAGE
  export GITLAB_URL=https://gitlab.example.com
  export GITLAB_TOKEN=glpat-xxxxxxxx
  export GITLAB_FALLBACK_ASSIGNEE=fred.smith

  python3 gitlab_secret_remediation.py --inspect-csv secrets.csv
  python3 gitlab_secret_remediation.py secrets.csv --dry-run
  python3 gitlab_secret_remediation.py secrets.csv
  python3 gitlab_secret_remediation.py secrets.csv --only-verified

IDEMPOTENCY
  TruffleHog's own numeric `id` column (when present) is used as the stable
  finding reference; a computed hash is the fallback when it's missing.
  Remediation branches are named security/secret-fix/<ref>, and issues/MRs
  are tagged with a matching label. Re-running the script skips findings
  that already have an open MR/Issue, and skips findings TruffleHog already
  marked rotated/resolved/false-positive via `date_rotated`/`triage_state`.
  Safe to re-run on a cron.
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, urlparse

try:
    import requests
except ImportError:
    print("This script requires the 'requests' package: pip install requests", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("secret-remediation")

SECURITY_LABEL = "security::secret-rotation"
BRANCH_PREFIX = "security/secret-fix"

# States that mean "TruffleHog/a human already dealt with this" -- skip them.
SKIP_TRIAGE_STATES = {"resolved", "false positive", "duplicate", "ignored", "accepted risk"}

# ---------------------------------------------------------------------------
# CSV column mapping -- see CSV SCHEMA in the module docstring. Edit this to
# match your actual TruffleHog export; run --inspect-csv to check first.
# ---------------------------------------------------------------------------
CANONICAL_COLUMNS = {
    "source":           ["source", "Source"],
    "repository":       ["repository", "Repository", "repo", "Repo"],
    "commit":           ["commit", "Commit", "CommitHash"],
    "url":              ["url", "URL", "link", "Link"],
    "trufflehog_link":  ["TruffleHog link", "trufflehog_link", "Trufflehog Link"],
    "file_path":        ["file_name", "File", "file_path", "FilePath", "Path"],
    "secret_type":      ["secret_type", "Secret Type", "Detector", "DetectorName"],
    "verified":         ["verified", "Verified"],
    "email":            ["email", "Email"],
    "username":         ["username", "Username"],
    "found_on":         ["found_on", "Found On"],
    "last_seen":        ["last_seen", "Last Seen"],
    "date_rotated":     ["date_rotated", "Date Rotated"],
    "triage_state":     ["triage_state", "Triage State"],
    "finding_id":       ["id", "Id", "ID"],
    "redacted":         ["redacted", "Redacted"],
}


def load_column_map(path: Optional[str]) -> dict:
    mapping = {k: v[:] for k, v in CANONICAL_COLUMNS.items()}
    if path:
        with open(path) as f:
            overrides = json.load(f)
        for canon, header in overrides.items():
            mapping[canon] = [header] if isinstance(header, str) else header
    return mapping


def build_header_lookup(fieldnames, column_map):
    """Return {canonical_name: actual_header_or_None} for one CSV file."""
    lower_map = {h.strip().lower(): h for h in fieldnames}
    resolved = {}
    for canon, candidates in column_map.items():
        found = None
        for cand in candidates:
            if cand.strip().lower() in lower_map:
                found = lower_map[cand.strip().lower()]
                break
        resolved[canon] = found
    return resolved


LINE_RE = re.compile(r"#L(\d+)")
NAME_EMAIL_RE = re.compile(r"^\s*(?P<name>.*?)\s*<(?P<email>[^>]+)>\s*$")


@dataclass
class Finding:
    source: str = ""
    repository: str = ""
    commit: str = ""
    url: str = ""
    trufflehog_link: str = ""
    file_path: str = ""
    secret_type: str = ""
    verified: str = ""
    committer_email: str = ""
    committer_name: str = ""
    found_on: str = ""
    last_seen: str = ""
    date_rotated: str = ""
    triage_state: str = ""
    trufflehog_finding_id: str = ""
    redacted: str = ""
    row_number: int = 0

    @property
    def line(self) -> str:
        m = LINE_RE.search(self.url or "")
        return m.group(1) if m else ""

    @property
    def ref(self) -> str:
        """Stable reference used for branch names / dedup. Prefers TruffleHog's
        own finding id; falls back to a computed hash if that column is absent."""
        if self.trufflehog_finding_id:
            return self.trufflehog_finding_id
        basis = "|".join([self.repository, self.commit, self.file_path, self.secret_type])
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]

    @property
    def is_gitlab_source(self) -> bool:
        return (self.source or "").strip().lower() == "gitlab"

    @property
    def already_handled(self) -> Optional[str]:
        """Returns a skip reason string if TruffleHog already marked this
        done, else None."""
        if self.date_rotated.strip():
            return f"already rotated on {self.date_rotated.strip()}"
        state = self.triage_state.strip().lower()
        if state in SKIP_TRIAGE_STATES:
            return f"triage_state={self.triage_state.strip()}"
        return None

    @property
    def is_code_finding(self) -> bool:
        return bool(self.commit) and bool(self.file_path)


def _parse_committer(raw_email_field: str):
    """The `email` column in this export is 'Full Name <addr@domain>'."""
    raw_email_field = (raw_email_field or "").strip()
    m = NAME_EMAIL_RE.match(raw_email_field)
    if m:
        return m.group("name"), m.group("email")
    if "@" in raw_email_field:
        return "", raw_email_field
    return raw_email_field, ""


def load_findings(csv_path: str, column_map: dict) -> list:
    findings = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV appears to have no header row")
        lookup = build_header_lookup(reader.fieldnames, column_map)
        missing_required = [c for c in ("repository", "commit", "source") if not lookup.get(c)]
        if missing_required:
            raise ValueError(
                f"Could not find required columns {missing_required} in CSV headers "
                f"{reader.fieldnames}. Use --column-map to fix, or --inspect-csv to see headers."
            )
        for i, row in enumerate(reader, start=2):  # header is row 1
            def get(canon):
                header = lookup.get(canon)
                return (row.get(header) or "").strip() if header else ""

            name, email = _parse_committer(get("email"))

            findings.append(Finding(
                source=get("source"),
                repository=get("repository"),
                commit=get("commit"),
                url=get("url"),
                trufflehog_link=get("trufflehog_link"),
                file_path=get("file_path"),
                secret_type=get("secret_type") or "unknown-secret-type",
                verified=get("verified"),
                committer_email=email,
                committer_name=name or get("username"),
                found_on=get("found_on"),
                last_seen=get("last_seen"),
                date_rotated=get("date_rotated"),
                triage_state=get("triage_state"),
                trufflehog_finding_id=get("finding_id"),
                redacted=get("redacted"),
                row_number=i,
            ))
    return findings


# ---------------------------------------------------------------------------
# GitLab API client
# ---------------------------------------------------------------------------

class GitLabError(Exception):
    pass


class GitLabClient:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        self.base = base_url.rstrip("/") + "/api/v4"
        self.session = requests.Session()
        self.session.headers.update({"PRIVATE-TOKEN": token})
        self.timeout = timeout
        self._project_cache = {}
        self._user_cache = {}

    def _req(self, method, path, ok_statuses=(200, 201), allow_404=False, **kwargs):
        url = f"{self.base}{path}"
        for attempt in range(3):
            resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 2))
                log.warning("Rate limited, sleeping %ss", wait)
                time.sleep(wait)
                continue
            if resp.status_code == 404 and allow_404:
                return None
            if resp.status_code not in ok_statuses:
                raise GitLabError(f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
            return resp.json() if resp.text else None
        raise GitLabError(f"{method} {path} failed after retries (rate limited)")

    # --- projects -----------------------------------------------------
    def get_project(self, repo_identifier: str) -> Optional[dict]:
        """repo_identifier may be a full clone URL, a web URL, or a path_with_namespace."""
        path = self._extract_project_path(repo_identifier)
        if not path:
            return None
        if path in self._project_cache:
            return self._project_cache[path]
        proj = self._req("GET", f"/projects/{quote(path, safe='')}", allow_404=True)
        self._project_cache[path] = proj
        return proj

    @staticmethod
    def _extract_project_path(identifier: str) -> Optional[str]:
        identifier = identifier.strip()
        if not identifier:
            return None
        if "://" in identifier:
            parsed = urlparse(identifier)
            path = parsed.path.strip("/")
        else:
            path = identifier.strip("/")
        if path.endswith(".git"):
            path = path[: -len(".git")]
        return path or None

    # --- commits / branches --------------------------------------------
    def get_commit(self, project_id, sha) -> Optional[dict]:
        return self._req("GET", f"/projects/{project_id}/repository/commits/{sha}", allow_404=True)

    def commit_branches(self, project_id, sha) -> list:
        refs = self._req(
            "GET", f"/projects/{project_id}/repository/commits/{sha}/refs",
            params={"type": "branch"}, allow_404=True,
        )
        return [r["name"] for r in refs] if refs else []

    def file_exists(self, project_id, branch, file_path) -> bool:
        result = self._req(
            "GET", f"/projects/{project_id}/repository/files/{quote(file_path, safe='')}",
            params={"ref": branch}, allow_404=True,
        )
        return result is not None

    def branch_exists(self, project_id, branch_name) -> bool:
        result = self._req(
            "GET", f"/projects/{project_id}/repository/branches/{quote(branch_name, safe='')}",
            allow_404=True,
        )
        return result is not None

    def create_branch(self, project_id, branch_name, ref):
        return self._req(
            "POST", f"/projects/{project_id}/repository/branches",
            params={"branch": branch_name, "ref": ref},
        )

    def commit_file_change(self, project_id, branch, file_path, content, commit_message, action="create"):
        payload = {
            "branch": branch,
            "commit_message": commit_message,
            "actions": [{"action": action, "file_path": file_path, "content": content}],
        }
        return self._req("POST", f"/projects/{project_id}/repository/commits", json=payload)

    # --- merge requests / issues ----------------------------------------
    def find_mr_by_source_branch(self, project_id, branch_name) -> Optional[dict]:
        results = self._req(
            "GET", f"/projects/{project_id}/merge_requests",
            params={"source_branch": branch_name, "state": "opened"},
        )
        return results[0] if results else None

    def create_merge_request(self, project_id, source_branch, target_branch, title, description, assignee_id=None, labels=None):
        payload = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description,
            "remove_source_branch": True,
            "labels": ",".join(labels or []),
        }
        if assignee_id:
            payload["assignee_id"] = assignee_id
        return self._req("POST", f"/projects/{project_id}/merge_requests", json=payload)

    def find_open_issue_by_label_and_title(self, project_id, search_text, label):
        results = self._req(
            "GET", f"/projects/{project_id}/issues",
            params={"state": "opened", "labels": label, "search": search_text},
        )
        return results[0] if results else None

    def create_issue(self, project_id, title, description, assignee_id=None, labels=None):
        payload = {
            "title": title,
            "description": description,
            "labels": ",".join(labels or []),
        }
        if assignee_id:
            payload["assignee_ids"] = [assignee_id]
        return self._req("POST", f"/projects/{project_id}/issues", json=payload)

    # --- users ------------------------------------------------------------
    def find_user_by_email(self, email) -> Optional[dict]:
        if not email:
            return None
        if email in self._user_cache:
            return self._user_cache[email]
        results = self._req("GET", "/users", params={"search": email})
        match = None
        for u in results or []:
            if (u.get("email") or u.get("public_email") or "").lower() == email.lower():
                match = u
                break
        if not match and results:
            match = results[0]  # best-effort fallback
        self._user_cache[email] = match
        return match

    def find_user_by_username(self, username) -> Optional[dict]:
        if not username:
            return None
        results = self._req("GET", "/users", params={"username": username})
        return results[0] if results else None

    def is_active_project_member(self, project_id, user_id) -> bool:
        member = self._req(
            "GET", f"/projects/{project_id}/members/all/{user_id}", allow_404=True,
        )
        return member is not None


# ---------------------------------------------------------------------------
# Assignment logic
# ---------------------------------------------------------------------------

def resolve_assignee(gl: GitLabClient, finding: Finding, project: dict, fallback_username: Optional[str]):
    """Returns (assignee_user_id_or_None, reason_string)."""
    user = gl.find_user_by_email(finding.committer_email)
    if user:
        active_account = user.get("state") == "active"
        still_member = gl.is_active_project_member(project["id"], user["id"])
        if active_account and still_member:
            return user["id"], f"original committer @{user['username']}"
        reason_bits = []
        if not active_account:
            reason_bits.append(f"account state={user.get('state')}")
        if not still_member:
            reason_bits.append("no longer a project member")
        log.info("Committer %s not usable (%s) -> falling back", finding.committer_email, ", ".join(reason_bits))
    else:
        log.info("Could not resolve GitLab user for committer email %r -> falling back", finding.committer_email)

    if fallback_username:
        # Accept either a GitLab username or an email address for this setting.
        if "@" in fallback_username:
            fb = gl.find_user_by_email(fallback_username)
        else:
            fb = gl.find_user_by_username(fallback_username)
        if fb:
            return fb["id"], f"fallback assignee @{fb['username']} (committer unresolved/inactive)"
        log.warning("Fallback assignee %r not found in GitLab (checked as %s)",
                    fallback_username, "email" if "@" in fallback_username else "username")
    return None, "no assignee resolved (left unassigned)"


# ---------------------------------------------------------------------------
# Content builders
# ---------------------------------------------------------------------------

CHECKLIST = """
### Remediation checklist
- [ ] Rotate/invalidate this credential at the source system immediately
- [ ] Check the provider's access logs for unauthorized use since exposure
- [ ] Replace the hardcoded secret with a reference to your secrets manager / CI/CD variable
- [ ] If the secret must be scrubbed from git history, coordinate a force-push with Security first
- [ ] Confirm remediation with Security, then close this {kind}
"""


def build_description(finding: Finding, project: dict, dangling: bool) -> str:
    commit_url = f"{project.get('web_url', '')}/-/commit/{finding.commit}" if finding.commit else ""
    lines = [
        f"**Secret type:** {finding.secret_type}",
        f"**Verified:** {finding.verified or 'unknown'}",
        f"**Repository:** {project.get('path_with_namespace', finding.repository)}",
    ]
    if finding.file_path:
        loc = finding.file_path + (f":{finding.line}" if finding.line else "")
        lines.append(f"**File:** `{loc}`")
    if finding.commit:
        lines.append(f"**Commit:** `{finding.commit}`" + (f" ({commit_url})" if commit_url else ""))
    if finding.url:
        lines.append(f"**Direct link:** {finding.url}")
    if finding.trufflehog_link:
        lines.append(f"**TruffleHog finding:** {finding.trufflehog_link}")
    if finding.committer_name or finding.committer_email:
        lines.append(f"**Original committer:** {finding.committer_name} <{finding.committer_email}>")
    if finding.found_on:
        lines.append(f"**First found:** {finding.found_on}")
    if finding.last_seen:
        lines.append(f"**Last seen:** {finding.last_seen}")
    lines.append(f"**Finding ref:** `{finding.ref}`")

    if dangling:
        lines.insert(0, (
            "> This secret is **not present in the current code** on any branch -- "
            "it was found in git history / GitLab logs (e.g. a dangling or superseded "
            "commit, or a file since removed). **The credential was still exposed at "
            "some point and must be rotated regardless.** No branch/MR could be "
            "attached to this finding, so it's tracked as an issue instead.\n"
        ))
        kind = "issue"
    else:
        kind = "MR"

    return "\n".join(lines) + "\n" + CHECKLIST.format(kind=kind)


def build_tracking_file(finding: Finding, project: dict) -> str:
    return (
        f"# Secret remediation tracker\n\n"
        f"Finding `{finding.ref}` opened by automated TruffleHog remediation tooling.\n\n"
        + build_description(finding, project, dangling=False)
    )


# ---------------------------------------------------------------------------
# Per-finding processing
# ---------------------------------------------------------------------------

def process_finding(gl: GitLabClient, finding: Finding, fallback_username: Optional[str], dry_run: bool) -> dict:
    result = {"ref": finding.ref, "row": finding.row_number, "repo": finding.repository, "source": finding.source}

    if not finding.is_gitlab_source:
        result.update(status="skipped-non-gitlab", detail=f"source={finding.source!r} is not a GitLab finding; route separately")
        return result

    handled_reason = finding.already_handled
    if handled_reason:
        result.update(status="skipped-already-handled", detail=handled_reason)
        return result

    project = gl.get_project(finding.repository)
    if not project:
        result.update(status="manual-review", detail="Could not resolve GitLab project from repository field")
        return result

    result["project"] = project["path_with_namespace"]

    if not finding.is_code_finding:
        return _handle_dangling(gl, finding, project, fallback_username, dry_run, result,
                                 reason="Finding is missing commit or file data (non-code source or incomplete row)")

    commit = gl.get_commit(project["id"], finding.commit)
    if not commit:
        return _handle_dangling(gl, finding, project, fallback_username, dry_run, result,
                                 reason="Commit no longer resolvable in this project (pruned/rewritten history)")

    branches = gl.commit_branches(project["id"], finding.commit)
    if not branches:
        return _handle_dangling(gl, finding, project, fallback_username, dry_run, result,
                                 reason="Commit exists but is not reachable from any branch (dangling / superseded)")

    default_branch = project.get("default_branch")
    target_branch = default_branch if default_branch in branches else branches[0]

    if finding.file_path and not gl.file_exists(project["id"], target_branch, finding.file_path):
        return _handle_dangling(gl, finding, project, fallback_username, dry_run, result,
                                 reason=f"File no longer exists on branch '{target_branch}' (moved/deleted since)")

    # Real, currently-reachable finding -> open an MR
    branch_name = f"{BRANCH_PREFIX}/{finding.ref}"
    tracking_path = f".security/secret-remediation/{finding.ref}.md"
    title = f"[Security] Rotate exposed secret: {finding.secret_type} in {finding.file_path}"

    existing_mr = gl.find_mr_by_source_branch(project["id"], branch_name)
    if existing_mr:
        result.update(status="skipped-exists", detail=f"Open MR already exists: {existing_mr['web_url']}")
        return result

    assignee_id, assignee_reason = resolve_assignee(gl, finding, project, fallback_username)
    description = build_description(finding, project, dangling=False)

    if dry_run:
        result.update(status="dry-run-mr", detail=f"Would open MR '{title}' on branch {branch_name} -> {target_branch}, assignee: {assignee_reason}")
        return result

    if gl.branch_exists(project["id"], branch_name):
        log.info("Branch %s already exists, reusing it", branch_name)
    else:
        gl.create_branch(project["id"], branch_name, target_branch)
        gl.commit_file_change(
            project["id"], branch_name, tracking_path,
            build_tracking_file(finding, project),
            commit_message=f"security: track remediation for finding {finding.ref}",
            action="create",
        )

    mr = gl.create_merge_request(
        project["id"], branch_name, target_branch, title, description,
        assignee_id=assignee_id, labels=[SECURITY_LABEL, "secret-rotation"],
    )
    result.update(status="created-mr", detail=f"{mr['web_url']} (assignee: {assignee_reason})")
    return result


def _handle_dangling(gl, finding, project, fallback_username, dry_run, result, reason):
    title = f"[Security] Rotate exposed secret (history-only): {finding.secret_type}"
    existing = gl.find_open_issue_by_label_and_title(project["id"], finding.ref, SECURITY_LABEL)
    if existing:
        result.update(status="skipped-exists", detail=f"Open issue already exists: {existing['web_url']}")
        return result

    assignee_id, assignee_reason = resolve_assignee(gl, finding, project, fallback_username)
    description = f"**Why an issue instead of an MR:** {reason}\n\n" + build_description(finding, project, dangling=True)
    description += f"\n\n`finding-ref:{finding.ref}`"

    if dry_run:
        result.update(status="dry-run-issue", detail=f"Would open issue '{title}', assignee: {assignee_reason} ({reason})")
        return result

    issue = gl.create_issue(
        project["id"], title, description,
        assignee_id=assignee_id, labels=[SECURITY_LABEL, "secret-rotation", "history-only"],
    )
    result.update(status="created-issue", detail=f"{issue['web_url']} (assignee: {assignee_reason})")
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_path", nargs="?", default="secrets.csv", help="Path to TruffleHog secrets.csv export")
    parser.add_argument("--dry-run", action="store_true", help="Don't create branches/MRs/issues, just report what would happen")
    parser.add_argument("--limit", type=int, default=None, help="Only process the first N findings (for testing)")
    parser.add_argument("--only-verified", action="store_true", help="Only process findings where verified is truthy")
    parser.add_argument("--column-map", help="Path to a JSON file overriding CANONICAL_COLUMNS mapping")
    parser.add_argument("--fallback-assignee", default=os.environ.get("GITLAB_FALLBACK_ASSIGNEE"),
                         help="GitLab username to assign when committer can't be resolved (default: $GITLAB_FALLBACK_ASSIGNEE)")
    parser.add_argument("--inspect-csv", action="store_true", help="Print detected CSV headers and column mapping, then exit")
    args = parser.parse_args()

    column_map = load_column_map(args.column_map)

    if args.inspect_csv:
        with open(args.csv_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
        lookup = build_header_lookup(headers, column_map)
        print("Detected CSV headers:", headers)
        print("\nResolved canonical -> header mapping:")
        for canon, header in lookup.items():
            print(f"  {canon:18s} -> {header}")
        unresolved = [c for c, h in lookup.items() if not h and c in ("repository", "commit", "source")]
        if unresolved:
            print(f"\nWARNING: required columns unresolved: {unresolved}. Use --column-map to fix.")
        return

    gitlab_url = os.environ.get("GITLAB_URL")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    if not gitlab_url or not gitlab_token:
        log.error("GITLAB_URL and GITLAB_TOKEN must be set in the environment")
        sys.exit(1)

    try:
        findings = load_findings(args.csv_path, column_map)
    except (FileNotFoundError, ValueError) as e:
        log.error(str(e))
        sys.exit(1)

    if args.only_verified:
        findings = [f for f in findings if f.verified.strip().lower() in ("true", "yes", "1")]
    if args.limit:
        findings = findings[: args.limit]
    log.info("Loaded %d findings to process from %s", len(findings), args.csv_path)

    gl = GitLabClient(gitlab_url, gitlab_token)
    results = []
    for finding in findings:
        try:
            r = process_finding(gl, finding, args.fallback_assignee, args.dry_run)
        except GitLabError as e:
            r = {"ref": finding.ref, "row": finding.row_number,
                 "repo": finding.repository, "status": "error", "detail": str(e)}
        results.append(r)
        log.info("[row %s] %s -> %s: %s", r["row"], r.get("repo"), r["status"], r.get("detail", ""))

    # Summary
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("\n=== Summary ===")
    for status, n in sorted(counts.items()):
        print(f"  {status:24s} {n}")
    print(f"  {'total':24s} {len(results)}")

    non_gitlab = [r for r in results if r["status"] == "skipped-non-gitlab"]
    if non_gitlab:
        by_source = {}
        for r in non_gitlab:
            by_source[r.get("source", "?")] = by_source.get(r.get("source", "?"), 0) + 1
        print("\nNon-GitLab findings skipped (route these through the appropriate channel):")
        for src, n in sorted(by_source.items()):
            print(f"  {src:20s} {n}")

    manual = [r for r in results if r["status"] in ("manual-review", "error")]
    if manual:
        print("\nNeed manual follow-up:")
        for r in manual:
            print(f"  row {r['row']} ({r.get('repo')}): {r.get('detail')}")


if __name__ == "__main__":
    main()
