#!/usr/bin/env python3
"""CVE enrichment module — retrieves vulnerability context from public databases.

Queries NVD, OSV, and GitHub Advisory APIs to augment vulnerability entries
with descriptions, CVSS scores, patch diffs, and reference URLs.
"""

import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

# --------------- HTTP helpers ---------------

def _get_json(url, timeout=15):
    """GET a URL and decode JSON. Returns None on any failure."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "ReachForge/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print("[enrichment] GET {} failed: {}".format(url, exc), file=sys.stderr)
        return None


def _get_text(url, timeout=15):
    """GET a URL and return text. Returns None on any failure."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "ReachForge/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print("[enrichment] GET {} failed: {}".format(url, exc), file=sys.stderr)
        return None


# --------------- NVD API v2 ---------------

def query_nvd(cve_id):
    """Query NVD API v2 for CVE details.

    Returns dict with keys: description, cvss_score, cvss_vector, references, nvd_cwe_ids
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}".format(
        urllib.request.quote(cve_id, safe="")
    )
    data = _get_json(url)
    if not data:
        return {}

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return {}

    cve_data = vulnerabilities[0].get("cve", {})

    # Extract English description
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Extract CVSS scores (try v3.1 first, then v3.0, then v2)
    cvss_score = None
    cvss_vector = ""
    metrics = cve_data.get("metrics", {})
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version_key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString", "")
            break

    # Extract references (deduplicated by URL)
    references = []
    seen_urls = set()
    for ref in cve_data.get("references", []):
        url_str = ref.get("url", "")
        if url_str and url_str not in seen_urls:
            seen_urls.add(url_str)
            tags = ref.get("tags", [])
            references.append({"url": url_str, "tags": tags})

    # Extract CWE from weaknesses (deduplicated)
    cwe_ids = []
    seen_cwes = set()
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in seen_cwes:
                seen_cwes.add(val)
                cwe_ids.append(val)

    result = {}
    if description:
        result["description"] = description
    if cvss_score is not None:
        result["cvss_score"] = cvss_score
    if cvss_vector:
        result["cvss_vector"] = cvss_vector
    if references:
        result["references"] = references
    if cwe_ids:
        result["nvd_cwe_ids"] = cwe_ids

    return result


# --------------- OSV API ---------------

def query_osv(cve_id):
    """Query OSV.dev for vulnerability details and fix commits."""
    url = "https://api.osv.dev/v1/vulns/{}".format(
        urllib.request.quote(cve_id, safe="")
    )
    data = _get_json(url)
    if not data:
        return {}

    result = {}

    if data.get("summary"):
        result["osv_summary"] = data["summary"]
    if data.get("details"):
        result["osv_details"] = data["details"]

    # Fix commits
    fix_commits = []
    for affected in data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    repo_url = rng.get("repo", "")
                    commit = event["fixed"]
                    fix_commits.append({"repo": repo_url, "commit": commit})

    if fix_commits:
        result["fix_commits"] = fix_commits

    # References
    references = []
    for ref in data.get("references", []):
        references.append({"type": ref.get("type", ""), "url": ref.get("url", "")})
    if references:
        result["osv_references"] = references

    return result


# --------------- GitHub Advisory API ---------------

def query_github_advisory(cve_id):
    """Query GitHub Advisory Database for vulnerability details."""
    url = "https://api.github.com/advisories?cve_id={}".format(
        urllib.request.quote(cve_id, safe="")
    )
    headers = {
        "User-Agent": "ReachForge/1.0",
        "Accept": "application/vnd.github+json",
    }

    # Use GitHub token if available for higher rate limits
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    if gh_token:
        headers["Authorization"] = "Bearer " + gh_token

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            advisories = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print("[enrichment] GitHub Advisory API failed: {}".format(exc), file=sys.stderr)
        return {}

    if not advisories:
        return {}

    adv = advisories[0]
    result = {}

    if adv.get("summary"):
        result["gh_summary"] = adv["summary"]
    if adv.get("description"):
        result["gh_description"] = adv["description"]
    if adv.get("severity"):
        result["gh_severity"] = adv["severity"]

    return result


# --------------- Patch fetching ---------------

_GITHUB_COMMIT_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})"
)

_GITHUB_PR_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/]+)/pull/(\d+)"
)


def _fetch_patch_diff(commit_url, max_bytes=50000):
    """Fetch a patch diff from a GitHub commit URL."""
    m = _GITHUB_COMMIT_RE.match(commit_url)
    if not m:
        return None

    patch_url = commit_url.rstrip("/") + ".patch"
    text = _get_text(patch_url, timeout=30)
    # Retry once on failure (transient network issues in Docker)
    if text is None:
        time.sleep(1)
        text = _get_text(patch_url, timeout=30)
    if text and len(text) > max_bytes:
        text = text[:max_bytes] + "\n... [truncated at {} bytes]".format(max_bytes)
    return text


def _fetch_pr_diff(pr_url, max_bytes=50000):
    """Fetch a patch diff from a GitHub pull request URL."""
    m = _GITHUB_PR_RE.match(pr_url)
    if not m:
        return None

    patch_url = pr_url.rstrip("/") + ".patch"
    text = _get_text(patch_url, timeout=30)
    if text is None:
        time.sleep(1)
        text = _get_text(patch_url, timeout=30)
    if text and len(text) > max_bytes:
        text = text[:max_bytes] + "\n... [truncated at {} bytes]".format(max_bytes)
    return text


def fetch_fix_patches(enrichment, max_patches=2):
    """Extract and fetch patch diffs from enrichment results."""
    patches = []

    # Collect commit URLs from various sources
    commit_urls = []

    # Collect PR URLs separately (fallback if commit diffs fail)
    pr_urls = []

    # From OSV fix commits
    for fc in enrichment.get("fix_commits", []):
        repo = fc.get("repo", "")
        commit = fc.get("commit", "")
        if "github.com" in repo and commit:
            repo_clean = repo.rstrip("/")
            if repo_clean.endswith(".git"):
                repo_clean = repo_clean[:-4]
            commit_urls.append(repo_clean + "/commit/" + commit)

    # From NVD references tagged as "Patch"
    for ref in enrichment.get("references", []):
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        if "Patch" in tags:
            if _GITHUB_COMMIT_RE.match(url):
                commit_urls.append(url)
            elif _GITHUB_PR_RE.match(url):
                pr_urls.append(url)

    # From OSV references
    for ref in enrichment.get("osv_references", []):
        url = ref.get("url", "")
        if _GITHUB_COMMIT_RE.match(url):
            commit_urls.append(url)
        elif _GITHUB_PR_RE.match(url):
            pr_urls.append(url)

    # Deduplicate and fetch (commits first, then PRs as fallback).
    # Dedup by commit hash (not just URL) so mirror repos pointing at the
    # same commit don't consume multiple slots.
    seen = set()
    seen_hashes = set()
    for url in commit_urls:
        normalized = url.rstrip("/")
        if normalized in seen:
            continue
        m = _GITHUB_COMMIT_RE.match(normalized)
        if m:
            commit_hash = m.group(2)
            if commit_hash in seen_hashes:
                continue
            seen_hashes.add(commit_hash)
        seen.add(normalized)
        patch = _fetch_patch_diff(normalized)
        if patch:
            patches.append(patch)
            if len(patches) >= max_patches:
                break

    # Fallback: fetch from PR URLs if not enough patches from commits
    if len(patches) < max_patches:
        for url in pr_urls:
            normalized = url.rstrip("/")
            if normalized not in seen:
                seen.add(normalized)
                patch = _fetch_pr_diff(normalized)
                if patch:
                    patches.append(patch)
                    if len(patches) >= max_patches:
                        break

    return patches


# --------------- Main enrichment function ---------------

def enrich_vulnerability(entry, cache_dir=None):
    """Enrich a vulnerability entry with data from NVD, OSV, and GitHub Advisory APIs.

    Args:
        entry: Vulnerability dict from vulnerabilities.json
        cache_dir: Optional Path for caching API responses

    Returns:
        New dict with additional fields merged into the entry.
        Original entry is not modified.
    """
    cve_id = entry.get("cve-id", "")
    if not cve_id:
        return dict(entry)

    # Check cache first
    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_file = cache_dir / (cve_id + ".enrichment.json")
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                # If cache has fix_commits but no patch_diffs, try fetching patches
                if cached.get("fix_commits") and not cached.get("patch_diffs"):
                    patches = fetch_fix_patches(cached)
                    if patches:
                        cached["patch_diffs"] = patches
                        print("[enrichment] Backfilled {} patch diff(s) into cache".format(len(patches)))
                        cache_file.write_text(json.dumps(cached, indent=2), encoding="utf-8")
                print("[enrichment] Using cached data for {}".format(cve_id))
                return _merge_enrichment(entry, cached)
            except Exception:
                pass

    print("[enrichment] Querying public databases for {} ...".format(cve_id))

    enrichment = {}

    # NVD
    nvd_data = query_nvd(cve_id)
    if nvd_data:
        enrichment.update(nvd_data)
        print("[enrichment] NVD: found description ({} chars), CVSS={}".format(
            len(nvd_data.get("description", "")),
            nvd_data.get("cvss_score", "N/A")
        ))
    else:
        print("[enrichment] NVD: no data found")

    time.sleep(0.5)

    # OSV
    osv_data = query_osv(cve_id)
    if osv_data:
        enrichment.update(osv_data)
        n_commits = len(osv_data.get("fix_commits", []))
        print("[enrichment] OSV: found {} fix commit(s)".format(n_commits))
    else:
        print("[enrichment] OSV: no data found")

    time.sleep(0.5)

    # GitHub Advisory
    gh_data = query_github_advisory(cve_id)
    if gh_data:
        enrichment.update(gh_data)
        print("[enrichment] GitHub Advisory: found severity={}".format(
            gh_data.get("gh_severity", "N/A")
        ))
    else:
        print("[enrichment] GitHub Advisory: no data found")

    # Fetch actual patch diffs
    patches = fetch_fix_patches(enrichment)
    if patches:
        enrichment["patch_diffs"] = patches
        print("[enrichment] Fetched {} patch diff(s)".format(len(patches)))

    # Cache results
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / (cve_id + ".enrichment.json")
        try:
            cache_file.write_text(json.dumps(enrichment, indent=2), encoding="utf-8")
        except Exception:
            pass

    return _merge_enrichment(entry, enrichment)


def _merge_enrichment(entry, enrichment):
    """Merge enrichment data into the vulnerability entry."""
    enriched = dict(entry)

    # Set description if not already present (NVD > OSV > GitHub fallback)
    if not enriched.get("description"):
        desc = (enrichment.get("description")
                or enrichment.get("osv_details")
                or enrichment.get("gh_description")
                or enrichment.get("osv_summary")
                or enrichment.get("gh_summary")
                or "")
        if desc:
            enriched["description"] = desc

    # Auto-populate CWE from NVD if not already set
    if not enriched.get("cwe-id"):
        nvd_cwes = enrichment.get("nvd_cwe_ids", [])
        if nvd_cwes:
            enriched["cwe-id"] = nvd_cwes[0]
            print("[enrichment] Auto-populated cwe-id: {}".format(nvd_cwes[0]))

    # Auto-derive affected-file FIRST (so function derivation can use it as context)
    if not enriched.get("affected-file"):
        desc = enriched.get("description", "")
        # Collect candidates from ALL patches, preferring description-mentioned files
        desc_match = ""
        first_source = ""
        for patch in enrichment.get("patch_diffs", []):
            fname = _extract_file_from_patch(patch, description=desc)
            if fname:
                # Check if this matches a file mentioned in the description
                if desc and fname.lower() in desc.lower():
                    desc_match = fname
                elif not first_source:
                    first_source = fname
        best_file = desc_match or first_source
        if best_file:
            enriched["affected-file"] = best_file
            print("[enrichment] Auto-derived affected-file from patch: {}".format(best_file))
        else:
            # Fallback: extract filename mentioned in descriptions when no
            # patches are available (e.g. "in tiff_jpeg.c in LibTIFF").
            fname = _extract_file_from_description(enriched, enrichment)
            if fname:
                enriched["affected-file"] = fname
                print("[enrichment] Auto-derived affected-file from description: {}".format(fname))

    # Auto-derive affected-function from all available sources (cascading).
    # We filter ``patch_diffs`` BEFORE derivation so hunk-header extraction
    # sees only the highest-scored sub-patches and isn't fooled by
    # noise commits (release tarballs, doc updates, copyright bumps).
    if enrichment.get("patch_diffs"):
        desc = enriched.get("description", "")
        afunc = enriched.get("affected-function", "")
        # Reuse the same keyword set the per-element filter would use.
        rank_keywords = ['security', 'vuln', 'CVE-', 'use-after-free',
                         'buffer overflow', 'heap overflow',
                         'heap-use-after-free', 'out-of-bounds',
                         'denial of service', 'double-free',
                         'null dereference', 'integer overflow']
        if afunc:
            rank_keywords.append(afunc)
        if desc:
            m = re.search(r'\bin\s+(?:the\s+)?(\w+)\s+function\b', desc)
            if m:
                rank_keywords.append(m.group(1))
            m = re.search(r'\bin\s+(\w+\.(?:c|h|cc|cpp))\b', desc)
            if m:
                rank_keywords.append(m.group(1))
        afile = enriched.get("affected-file", "")

        scored_diffs = []
        for pd in enrichment["patch_diffs"]:
            try:
                filt = _filter_security_patches(pd, description=desc,
                                                affected_function=afunc)
            except Exception:
                filt = pd
            if not filt or not filt.strip():
                continue
            try:
                sc = _score_sub_patch(filt, rank_keywords, afile)
            except Exception:
                sc = 0.0
            scored_diffs.append((sc, filt))
        # Sort descending by score so patch_diffs[0] is the highest-ranked
        # commit (the real security fix), not a release-tidy noise commit.
        scored_diffs.sort(key=lambda x: x[0], reverse=True)
        cleaned = [s for _, s in scored_diffs]
        enrichment["patch_diffs"] = cleaned
        enriched["patch_diffs"] = cleaned

    if not enriched.get("affected-function"):
        func = _derive_affected_function(enriched, enrichment)
        if func:
            enriched["affected-function"] = func

    # CVSS data
    if enrichment.get("cvss_score") is not None:
        enriched["cvss_score"] = enrichment["cvss_score"]
    if enrichment.get("cvss_vector"):
        enriched["cvss_vector"] = enrichment["cvss_vector"]

    # Extract and store trigger condition analysis from the filtered patch diff
    if enriched.get("patch_diffs") and not enriched.get("trigger_condition"):
        try:
            desc = enriched.get("description", "")
            trigger = extract_trigger_condition(enriched["patch_diffs"][0], desc)
            if trigger:
                enriched["trigger_condition"] = trigger
                print("[enrichment] Extracted trigger condition from patch diff")
        except Exception as exc:
            print("[enrichment] Warning: trigger condition extraction failed ({}), skipping".format(exc),
                  file=sys.stderr)

    # Fix commit references
    if enrichment.get("fix_commits"):
        enriched["fix_commits"] = enrichment["fix_commits"]

    # Severity from GitHub
    if enrichment.get("gh_severity"):
        enriched["severity"] = enrichment["gh_severity"]

    # Supplementary references (deduplicated)
    all_refs = []
    for ref in enrichment.get("references", []):
        all_refs.append(ref.get("url", ""))
    for ref in enrichment.get("osv_references", []):
        all_refs.append(ref.get("url", ""))
    all_refs = [r for r in all_refs if r]
    if all_refs:
        enriched["enrichment_references"] = list(dict.fromkeys(all_refs))

    return enriched


# --------------- Field extraction helpers ---------------

_FUNC_IN_DESC_RE = re.compile(
    r'\b(?:in|via|the|function)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+(?:function|in)\b'
    r'|'
    r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s+function\b'
    r'|'
    r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\b'
)


# Words that should never be returned as function names — they appear in
# CVE descriptions but are English prose, not C/C++ identifiers.
_FUNCTION_NAME_BLOCKLIST = frozenset([
    'a', 'an', 'the', 'this', 'that', 'which', 'when', 'where', 'how',
    'allows', 'allow', 'cause', 'causes', 'leading', 'leads', 'results',
    'remote', 'local', 'attacker', 'attackers', 'user', 'denial',
    'service', 'certain', 'crafted', 'input', 'file', 'data',
    'before', 'after', 'through', 'because', 'via', 'has', 'have',
    'could', 'can', 'may', 'might', 'would', 'application', 'server',
    'client', 'code', 'execution', 'memory', 'stack', 'heap',
    'buffer', 'overflow', 'underflow', 'integer', 'null', 'pointer',
    'dereference', 'vulnerability', 'issue', 'bug', 'flaw', 'error',
    'version', 'versions', 'prior', 'component', 'module', 'library',
    'parameter', 'argument', 'return', 'value', 'size', 'length',
    'type', 'undefined', 'behavior', 'behaviour',
    # Short prepositions / conjunctions that regex patterns may capture
    'at', 'by', 'to', 'from', 'is', 'or', 'if', 'on', 'so', 'up',
    'do', 'no', 'be', 'it', 'as', 'of', 'for', 'not', 'but', 'was',
    'are', 'were', 'been', 'its', 'into', 'with', 'other', 'some',
    'also', 'than', 'such', 'only', 'out', 'over', 'then',
    # Common file/document names that are not functions
    'changes', 'changelog', 'readme', 'news', 'authors', 'todo',
    'history', 'install', 'copying', 'license', 'contributing',
    'makefile', 'configure', 'release', 'summary', 'update',
    'bump', 'sync', 'merge', 'revert', 'doc', 'docs', 'tests',
    # Common directory/module prefixes used in commit messages
    'lib', 'src', 'core', 'utils', 'util', 'pkg', 'cmd', 'api',
    'app', 'web', 'build', 'infra', 'tools', 'internal', 'include',
    # Adverbs / English words that pass plausibility but are not functions
    'internally', 'externally', 'previously', 'optionally',
    # Standard library / POSIX functions mentioned as symptoms in CVE
    # descriptions — never the real target for fuzzing
    'memmove', 'memcpy', 'memset', 'memcmp', 'memchr',
    'strlen', 'strcmp', 'strncmp', 'strcpy', 'strncpy',
    'strcat', 'strncat', 'strstr', 'strchr', 'strrchr', 'strtol', 'strtoul',
    'malloc', 'calloc', 'realloc', 'free',
    'printf', 'fprintf', 'sprintf', 'snprintf', 'sscanf', 'scanf', 'vsnprintf',
    'read', 'write', 'open', 'close', 'fopen', 'fclose', 'fread', 'fwrite',
    'abort', 'exit', 'assert',
    # C/C++ language keywords — never function names; show up in hunk
    # headers when the diff context is inside a control-flow block at top
    # scope (e.g. ``@@ ... @@ while (*cc != XCL_END)``).
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default',
    'return', 'break', 'continue', 'goto', 'sizeof', 'static',
    'const', 'extern', 'inline', 'register', 'volatile', 'auto',
    'struct', 'union', 'enum', 'typedef', 'class', 'public',
    'private', 'protected', 'namespace', 'template', 'typename',
    'using', 'virtual', 'override', 'final', 'try', 'catch', 'throw',
    'new', 'delete', 'operator', 'friend', 'explicit', 'mutable',
    'void', 'int', 'char', 'short', 'long', 'float', 'double',
    'signed', 'unsigned', 'bool', 'true', 'false',
    # Preprocessor leftovers
    'endif', 'ifdef', 'ifndef', 'define', 'undef', 'pragma', 'include',
])


def _is_plausible_c_function(name):
    """Return True if *name* looks like a real C/C++ function identifier."""
    if not name or len(name) < 2:
        return False
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False
    if name.lower() in _FUNCTION_NAME_BLOCKLIST:
        return False
    # Reject ALL-CAPS names that look like macros/constants (>= 4 chars)
    if len(name) >= 4 and name == name.upper():
        return False
    return True


def _score_candidate(name, base_score):
    """Adjust *base_score* for candidate *name* using simple heuristics."""
    score = base_score
    if '_' in name:
        score += 2  # C naming convention bonus
    if len(name) >= 5:
        score += 1
    if len(name) < 4:
        score -= 2  # very short names are rarely real function identifiers
    return score


# Ordered extraction patterns.  Each entry:
#   (compiled_regex, capture_group_index, base_score)
# Patterns are tried via finditer; ALL matches are collected and ranked.
_FUNC_EXTRACT_PATTERNS = [
    # "in the FUNC function" / "in the FUNC() function"
    (re.compile(r'\bin\s+(?:the\s+)?([a-zA-Z_]\w+)\s*(?:\(\))?\s+function\b', re.IGNORECASE), 1, 10),
    # "the FUNC function" / "the FUNC() function"
    (re.compile(r'\bthe\s+([a-zA-Z_]\w+)\s*(?:\(\))?\s+function\b', re.IGNORECASE), 1, 9),
    # "via FUNC in file.c" / "via FUNC() at /path/file.c"
    (re.compile(r'\bvia\s+(?:the\s+)?([a-zA-Z_]\w+)(?:\(\))?\s+(?:in|at)\s+[\w/.]+\.\w+', re.IGNORECASE), 1, 9),
    # "demonstrated by FUNC" / "evidenced by FUNC" / "shown by FUNC"
    (re.compile(r'\b(?:demonstrated|evidenced|illustrated|shown|triggered)\s+by\s+([a-zA-Z_]\w+)', re.IGNORECASE), 1, 9),
    # back-ticked: `FUNC` or `FUNC()`
    (re.compile(r'`([a-zA-Z_]\w+?)(?:\(\))?`'), 1, 12),
    # FUNC() call syntax in prose
    (re.compile(r'\b([a-zA-Z_]\w+)\(\)'), 1, 8),
    # C++ qualified name — Class::Method or ns::func
    (re.compile(r'\b[a-zA-Z_]\w+::([a-zA-Z_]\w+)'), 1, 8),
    # "function FUNC" (high false-positive — scores lower)
    (re.compile(r'\bfunction\s+([a-zA-Z_]\w+)\b', re.IGNORECASE), 1, 5),
    # "in FUNC," or "in FUNC." (end-of-clause, requires _ or mixedCase)
    (re.compile(r'\bin\s+([a-zA-Z_]\w{2,})\s*[,.]', re.IGNORECASE), 1, 3),
]


def _extract_function_from_description(description):
    """Extract the most likely affected C/C++ function name from *description*.

    Runs ALL regex patterns, collects every plausible candidate with a
    confidence score, and returns the highest-scored name.  This avoids the
    problem of an early low-confidence pattern short-circuiting before a
    better match is found later.
    """
    if not description:
        return ""

    # Collect (name, (score, first_pos)) from every pattern.
    # first_pos tracks the earliest match position in the description so
    # that tied scores are broken by textual order (important on Python < 3.7
    # where dict iteration order is not guaranteed).
    candidates = {}  # name -> (score, first_pos)
    for pat, group, base in _FUNC_EXTRACT_PATTERNS:
        for m in pat.finditer(description):
            name = m.group(group)
            if not _is_plausible_c_function(name):
                continue
            # Extra guard for the weak end-of-clause pattern
            if base <= 3:
                if '_' not in name and (name == name.lower() or name == name.upper()):
                    continue
            score = _score_candidate(name, base)
            pos = m.start()
            if name not in candidates or score > candidates[name][0]:
                candidates[name] = (score, pos)
            elif score == candidates[name][0] and pos < candidates[name][1]:
                candidates[name] = (score, pos)

    if not candidates:
        return ""

    # Discard candidates that are actually file basenames (e.g. "tiff_jpeg"
    # from "in tiff_jpeg.c") — these are filenames, not function names.
    for name in list(candidates):
        pat = re.compile(r'\b' + re.escape(name) + r'\.(?:c|h|cc|cpp|cxx|hpp|hh)\b', re.IGNORECASE)
        if pat.search(description):
            del candidates[name]

    if not candidates:
        return ""

    # Return the candidate with the highest score; ties broken by earliest
    # position in the description (lower pos wins via negation).
    return max(candidates, key=lambda n: (candidates[n][0], -candidates[n][1]))


# C/C++ source file extensions for filtering security-relevant patches
_SOURCE_EXTS = frozenset(('.c', '.h', '.cc', '.cpp', '.cxx', '.hh', '.hpp'))


def _split_sub_patches(patch_text):
    """Split a multi-commit patch (e.g. from a merge commit) into individual
    sub-patches.  Each sub-patch starts with 'From <hash>'."""
    if not patch_text:
        return []
    # Find all "From <40-char-hex>" boundary positions
    starts = [m.start() for m in re.finditer(
        r'^From [0-9a-f]{40} ', patch_text, flags=re.MULTILINE)]
    if not starts:
        return [patch_text]
    parts = []
    # Include any text before the first "From" marker
    if starts[0] > 0:
        prefix = patch_text[:starts[0]].strip()
        if prefix:
            parts.append(prefix)
    for i, s in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(patch_text)
        parts.append(patch_text[s:end])
    return [p for p in parts if p.strip()]


def _sub_patch_touches_source(sub_patch):
    """Return True if the sub-patch modifies at least one C/C++ source file."""
    for line in sub_patch.split('\n'):
        if line.startswith('+++ b/') or line.startswith('--- a/'):
            path = line[6:].strip()
            ext = os.path.splitext(path)[1].lower()
            if ext in _SOURCE_EXTS:
                return True
        # Also check 'diff --git a/path b/path' lines for patches that lack
        # explicit --- a/ / +++ b/ headers.
        if line.startswith('diff --git '):
            m = re.search(r'diff --git a/(\S+)', line)
            if m:
                ext = os.path.splitext(m.group(1))[1].lower()
                if ext in _SOURCE_EXTS:
                    return True
    return False


def _patch_has_file_headers(patch_text):
    """Return True if the patch contains explicit file-path headers."""
    for line in patch_text.split('\n'):
        if line.startswith('+++ b/') or line.startswith('--- a/') or line.startswith('diff --git '):
            return True
    return False


def _sub_patch_mentions(sub_patch, keywords):
    """Return True if the sub-patch references any of the keywords (case
    insensitive) in its **commit message** or **diff hunk content** only.

    Excluded zones (match filenames too broadly):
    - Diffstat block: the file-listing between the ``---`` separator and the
      first ``diff --git`` line (e.g. `` expat/lib/xmlparse.c | 2 +-``).
    - Diff file-path headers: ``diff --git a/… b/…``, ``--- a/…``, ``+++ b/…``.
    - Diff metadata: ``index …``, ``old mode …``, ``new mode …``.
    """
    lines = sub_patch.split('\n')
    searchable_parts = []
    in_diffstat = False
    in_diff_meta = False  # between 'diff --git' and next '@@'
    in_hunk = False       # inside hunk content (after '@@')
    for line in lines:
        # Bare '---' line ends the commit message and starts the diffstat
        if not in_diffstat and not in_diff_meta and not in_hunk and line.strip() == '---':
            in_diffstat = True
            continue
        # 'diff --git' ends any diffstat and starts diff metadata
        if line.startswith('diff --git '):
            in_diffstat = False
            in_diff_meta = True
            in_hunk = False
            continue
        # Skip diff file-path headers
        if line.startswith('--- ') or line.startswith('+++ '):
            continue
        # @@ marks the start of hunk content
        if line.startswith('@@'):
            in_diff_meta = False
            in_diffstat = False
            in_hunk = True
            continue
        # Skip diff metadata lines
        if in_diff_meta and (line.startswith('index ') or line.startswith('old mode') or line.startswith('new mode')):
            continue
        # Skip diffstat lines (file listings, summary line)
        if in_diffstat:
            continue
        # In hunk content: only search actual changed lines (+/-), not
        # context lines (space-prefixed) which can mention filenames or
        # functions incidentally.
        if in_hunk and not (line.startswith('+') or line.startswith('-')):
            continue
        # Include: commit message (before diffstat) and hunk changed lines
        searchable_parts.append(line)
    searchable = '\n'.join(searchable_parts).lower()
    return any(kw.lower() in searchable for kw in keywords if kw)


# Patterns that indicate a changed line is purely a version/copyright bump,
# not a behavioural code change.
_VERSION_BUMP_RE = re.compile(
    r'(?i)(?:'
    r'#\s*define\s+\w*(?:VER|MAJOR|MINOR|PATCH|BUILD|RELEASE)\w*'
    r'|VERSION\s*[:=]'
    r'|\bversion\b.*\b\d+\.\d+'
    r'|Copyright\b'
    r'|\bAC_INIT\b'
    r'|\bcmake_minimum_required\b'
    r'|\bset\s*\(\s*\w*(?:VERSION|VER)\w*'
    r'|\bAC_PREREQ\b'
    r'|\bAM_INIT_AUTOMAKE\b'
    r'|\bRelease\b.*\b\d+\.\d+'
    r')',
)

_HUNK_HEADER_RE = re.compile(r'^@@\s')

# Lines that look like cosmetic / metadata noise rather than real code
# changes.  Used by ``extract_trigger_condition`` to keep
# ``vulnerable_lines`` / ``fix_lines`` focused on actual program behaviour.
_PURE_NOISE_RE = re.compile(
    r'(?i)('
    r'copyright\b'
    r'|all rights reserved'
    r'|last updated\s*:'
    r'|^\s*version\s+\d+\.\d+'
    r'|^\s*release\s+\d+\.\d+'
    r'|^\s*<[a-z!/][^>]*>\s*$'              # standalone HTML/SGML tag
    r'|^\s*[-=*#]{3,}\s*$'                   # horizontal rules
    r'|^\s*\*\s*$'                           # bare comment marker
    r'|^\s*//\s*$'
    r')',
)


def _is_version_bump_only(patch_text):
    """Return True if every changed hunk line in source files is a version/copyright bump.

    This catches release-tag commits (e.g. "Release libpng 1.6.51") that only
    update version macros and copyright strings in C/C++ source files, with no
    behavioural code changes.
    """
    in_source_hunk = False
    in_source_file = False
    has_source_changes = False
    for line in patch_text.splitlines():
        # Track which file we're in
        if line.startswith('+++ b/') or line.startswith('+++ a/'):
            fname = line.split('/', 1)[-1] if '/' in line else line
            ext = '.' + fname.rsplit('.', 1)[-1] if '.' in fname else ''
            in_source_file = ext.lower() in _SOURCE_EXTS
            in_source_hunk = False
            continue
        if _HUNK_HEADER_RE.match(line):
            in_source_hunk = in_source_file
            continue
        if not in_source_hunk:
            continue
        # Only examine actually changed lines (skip context)
        if not (line.startswith('+') or line.startswith('-')):
            continue
        content = line[1:]
        # Blank/whitespace-only changed lines are harmless
        if not content.strip():
            continue
        has_source_changes = True
        if not _VERSION_BUMP_RE.search(content):
            return False  # Found a real code change
    return has_source_changes  # True only if we saw changes and ALL were version bumps


# Sub-patch scoring signals (generic; no library/CVE knowledge).
_FIX_SUBJECT_TOKENS = (
    'fix', 'vuln', 'overflow', 'out-of-bound', 'out of bound',
    'use-after-free', 'use after free', 'double-free', 'double free',
    'null', 'leak', 'crash', 'segfault', 'cve-', 'security',
    'deref', 'shift', 'negative', 'race', 'infinite', 'recursion',
    'exhaust', 'sanitize', 'oob', 'uaf',
)
_NOISE_SUBJECT_TOKENS = (
    'tidy', 'release', 'version bump', 'changelog', 'readme',
    'documentation', 'doc:', 'whitespace', 'spelling', 'typo',
    'comment:', 'lint', 'format', 'reformat', 'cosmetic',
    'rename ', 'move ', 'merge branch', 'merge pull request',
)
_DOC_PATH_HINTS = (
    '.md', '.rst', '.txt', '/doc/', '/docs/', '/news', '/changelog',
    '/readme', '.html', '.pdf', '.bib', '.po', '/man/', '.1', '.3',
)
_META_PATH_HINTS = (
    'cmakelists', 'configure.ac', 'configure.in', 'makefile', '.am',
    'license', 'authors', '.cmake', '.pc.in', '.spec',
)
_SUBJECT_RE = re.compile(
    r'^Subject:\s*(?:\[PATCH(?:\s+\d+/\d+)?\]\s*)?(.*)$',
    flags=re.MULTILINE,
)
_CVE_ID_RE = re.compile(r'\bcve-\d{4}-\d{4,7}\b', re.IGNORECASE)


def _score_sub_patch(sub_patch, keywords, affected_file=""):
    """Heuristic relevance score for a sub-patch (higher = more likely the
    real security fix).  All signals are generic — no per-library logic.

    Combines: commit-subject tokens, file-set composition, affected-file
    hit, and density of *substantive* (non-whitespace, non-version-bump)
    +/- changes.
    """
    if not sub_patch:
        return -100.0
    score = 0.0

    msubj = _SUBJECT_RE.search(sub_patch)
    subject = (msubj.group(1) if msubj else "").strip().lower()
    if subject:
        if any(tok in subject for tok in _FIX_SUBJECT_TOKENS):
            score += 4.0
        if any(tok in subject for tok in _NOISE_SUBJECT_TOKENS):
            score -= 5.0
        if _CVE_ID_RE.search(subject):
            score += 5.0

    # Body / hunk keyword match (re-uses existing _sub_patch_mentions which
    # excludes diffstat and file-header lines).
    if keywords and _sub_patch_mentions(sub_patch, keywords):
        score += 2.0

    # File-set composition.
    file_paths = []
    for line in sub_patch.split('\n'):
        if line.startswith('diff --git '):
            m = re.search(r'diff --git a/(\S+)', line)
            if m:
                file_paths.append(m.group(1))
    n_files = len(file_paths)
    n_source = sum(
        1 for p in file_paths
        if os.path.splitext(p)[1].lower() in _SOURCE_EXTS
    )
    pl = [p.lower() for p in file_paths]
    n_doc = sum(
        1 for p in pl if any(h in p or p.endswith(h) for h in _DOC_PATH_HINTS)
    )
    n_meta = sum(
        1 for p in pl if any(h in p for h in _META_PATH_HINTS)
    )

    if n_files >= 8:
        score -= 2.0
    if n_files >= 20:
        score -= 4.0  # release-tidy-style sprawl
    if 1 <= n_source <= 3 and n_doc <= 1 and n_meta <= 1:
        score += 3.0
    if n_files > 0 and (n_doc + n_meta) > n_source:
        score -= 3.0

    if affected_file:
        af = affected_file.lower()
        # Match on basename or path substring
        if any(af in p for p in pl):
            score += 4.0

    # Substantive change density: count +/- lines after stripping
    # whitespace, comment, copyright/version-bump lines.
    real_changes = 0
    for line in sub_patch.split('\n'):
        if not line or line[0] not in '+-':
            continue
        if line.startswith('+++') or line.startswith('---'):
            continue
        body = line[1:]
        s = body.strip()
        if not s:
            continue
        if _VERSION_BUMP_RE.search(body):
            continue
        if s.startswith('//') or s.startswith('*') or s.startswith('/*') \
                or s.startswith('#') or s.startswith('--'):
            continue
        real_changes += 1

    if 1 <= real_changes <= 50:
        score += 3.0
    elif real_changes > 200:
        score -= 3.0
    elif real_changes == 0:
        score -= 6.0  # whitespace / copyright only

    return score


def _filter_security_patches(patch_text, description="", affected_function=""):
    """Filter a multi-commit patch diff to only the security-relevant sub-patch(es).

    Strategy:
    1. Split into individual sub-patches (one per 'From <hash>' block).
    2. Drop sub-patches that don't touch C/C++ source.
    3. Score each survivor with ``_score_sub_patch`` and rank descending.
    4. Keep the top-scored sub-patch; additionally keep any other survivors
       with positive score.  If all scores are ≤ 0, keep only the top one
       (defensive — never lose the patch entirely).
    """
    subs = _split_sub_patches(patch_text)

    # Even single-commit patches must touch at least one C/C++ source file;
    # otherwise the patch is irrelevant (e.g. CONTRIBUTORS.md, README).
    # Patches without explicit file headers (bare hunks) are allowed through.
    if len(subs) <= 1:
        if _patch_has_file_headers(patch_text) and not _sub_patch_touches_source(patch_text):
            return ""  # non-source patch — discard
        # Reject version/copyright-only bumps (e.g. release-tag commits)
        if _is_version_bump_only(patch_text):
            return ""
        return patch_text  # single source-touching commit or bare hunk — keep

    # Build keyword list from CVE description — use specific terms that
    # distinguish the security fix from housekeeping commits.
    keywords = ['security', 'vuln', 'CVE-', 'use-after-free',
                'buffer overflow', 'heap overflow', 'heap-use-after-free',
                'out-of-bounds', 'denial of service', 'double-free',
                'null dereference', 'integer overflow']
    if affected_function:
        keywords.append(affected_function)
    # Extract function name from description (e.g. "doContent function")
    if description:
        m = re.search(r'\bin\s+(?:the\s+)?(\w+)\s+function\b', description)
        if m:
            keywords.append(m.group(1))
        # Also grab filename mentions like "in xmlparse.c"
        m = re.search(r'\bin\s+(\w+\.(?:c|h|cc|cpp))\b', description)
        if m:
            keywords.append(m.group(1))

    # Filter: must touch C/C++ source
    source_subs = [s for s in subs if _sub_patch_touches_source(s)]
    if not source_subs:
        return ""  # nothing relevant

    # Score and rank — extract affected_file from description for scoring.
    affected_file = ""
    if description:
        m = re.search(r'\bin\s+(\w+\.(?:c|h|cc|cpp|cxx|hh|hpp))\b', description)
        if m:
            affected_file = m.group(1)

    scored = [(_score_sub_patch(s, keywords, affected_file), s)
              for s in source_subs]
    scored.sort(key=lambda x: x[0], reverse=True)

    top_score = scored[0][0]
    # Keep top + any other clearly positive scorers.  If everything is
    # non-positive, keep only the top to avoid losing the patch entirely.
    kept = [scored[0][1]]
    for sc, s in scored[1:]:
        if sc > 0 and sc >= top_score - 2.0:
            kept.append(s)

    return '\n'.join(kept)


def _extract_file_from_description(enriched, enrichment):
    """Extract the affected filename from description text when no patches exist.

    Scans the same description sources as function extraction and looks for
    C/C++ filenames like ``tiff_jpeg.c`` or ``xmlparse.c``.
    """
    _file_re = re.compile(r'\bin\s+(\w+\.(?:c|h|cc|cpp|cxx))\b', re.IGNORECASE)
    sources = [
        enriched.get("description", ""),
        enrichment.get("description", ""),
        enrichment.get("osv_details", ""),
        enrichment.get("gh_description", ""),
    ]
    seen = set()
    for text in sources:
        if not text or text in seen:
            continue
        seen.add(text)
        m = _file_re.search(text)
        if m:
            return m.group(1)
    return ""


def _extract_file_from_patch(patch_text, description=""):
    """Extract the primary affected filename from a patch diff.

    Prefers C/C++ source files.  If the CVE description mentions a filename,
    prioritize that file.  Falls back to the first +++ b/ line.
    """
    if not patch_text:
        return ""

    # Check if the CVE description mentions a specific file
    desc_file = ""
    if description:
        # Pattern 1: "in FILENAME" (e.g., "overflow in xmlparse.c")
        m = re.search(r'\bin\s+(\w+\.(?:c|h|cc|cpp|cxx))\b', description)
        if m:
            desc_file = m.group(1).lower()
        else:
            # Pattern 2: "FILENAME in PROJECT" (e.g., "xmltok_impl.c in Expat")
            m = re.search(r'\b(\w+\.(?:c|h|cc|cpp|cxx))\s+in\b', description)
            if m:
                desc_file = m.group(1).lower()

    # Collect all files from the diff, separating implementation files
    # (.c/.cc/.cpp/.cxx) from headers (.h/.hh/.hpp).  The actual bug almost
    # always lives in the implementation; headers are usually touched only
    # to update declarations / type signatures.
    impl_exts = frozenset(('.c', '.cc', '.cpp', '.cxx'))
    impl_files = []
    header_files = []
    other_files = []
    for line in patch_text.split('\n'):
        if line.startswith('+++ b/'):
            path = line[6:].strip()
            fname = path.rsplit('/', 1)[-1] if '/' in path else path
            ext = os.path.splitext(fname)[1].lower()
            if ext in _SOURCE_EXTS:
                # If it matches the description, return immediately
                if desc_file and fname.lower() == desc_file:
                    return fname
                if ext in impl_exts:
                    impl_files.append(fname)
                else:
                    header_files.append(fname)
            else:
                other_files.append(fname)

    source_files = impl_files + header_files

    # Prefer C/C++ source file mentioned in description
    if desc_file:
        for f in source_files:
            if desc_file in f.lower():
                return f

    # Prefer implementation file over header
    if impl_files:
        return impl_files[0]
    if header_files:
        return header_files[0]
    # No source files found — return empty rather than a non-source file
    # (e.g. CONTRIBUTORS.md) which would poison downstream analysis.
    return ""


def extract_trigger_condition(patch_text, description=""):
    """Extract a structured trigger condition from a patch diff and CVE description.

    Analyzes the removed (-) lines in the diff to identify what specific
    code was vulnerable, and the added (+) lines to understand what the fix
    changed (bounds checks, type changes, overflow guards, etc.).

    Returns a dict with:
      - vulnerable_lines: key removed lines from the patch
      - fix_lines: key added lines showing the fix
      - affected_functions: functions modified in the patch (from @@ headers)
      - trigger_summary: human-readable summary of what triggers the bug
    """
    if not patch_text:
        return {}

    # If the patch explicitly names files (via diff headers) but NONE are
    # C/C++ source files, there is nothing useful to extract.
    # Patches with no file headers (bare hunks) are allowed through.
    if _patch_has_file_headers(patch_text) and not _sub_patch_touches_source(patch_text):
        return {}

    vulnerable_lines = []
    fix_lines = []
    affected_functions = []
    hunk_context = []

    in_diff = False
    current_func = ""

    for line in patch_text.split('\n'):
        # Track which function we're in via @@ hunk headers
        if line.startswith('@@'):
            in_diff = True
            # Extract function name from hunk header: @@ -n,n +n,n @@ type func_name(
            m = re.search(r'@@[^@]+@@\s*(?:\w+\s+)*(\w+)\s*\(', line)
            if m:
                current_func = m.group(1)
                if current_func not in affected_functions:
                    affected_functions.append(current_func)
            hunk_context.append(line)
            continue

        if not in_diff:
            continue

        # Collect removed (vulnerable) lines — skip pure whitespace changes
        if line.startswith('-') and not line.startswith('---'):
            stripped = line[1:].strip()
            if (stripped and len(stripped) > 3
                    and len(stripped) <= 300
                    and not _VERSION_BUMP_RE.search(stripped)
                    and not _PURE_NOISE_RE.search(stripped)):
                vulnerable_lines.append(stripped)

        # Collect added (fix) lines
        if line.startswith('+') and not line.startswith('+++'):
            stripped = line[1:].strip()
            if (stripped and len(stripped) > 3
                    and len(stripped) <= 300
                    and not _VERSION_BUMP_RE.search(stripped)
                    and not _PURE_NOISE_RE.search(stripped)):
                fix_lines.append(stripped)

    # Build trigger summary by combining description + diff analysis
    trigger_parts = []

    if description:
        # Extract numeric thresholds from description
        nums = re.findall(r'\b(\d+)\s+(?:or more|bytes|elements|attributes|characters|places)', description)
        if nums:
            trigger_parts.append("Threshold value from advisory: {}".format(", ".join(nums)))

        # Extract specific operations mentioned
        ops = re.findall(r'(?:left shift|right shift|overflow|underflow|out.of.bounds|buffer over|integer overflow|realloc|malloc|free)', description, re.IGNORECASE)
        if ops:
            trigger_parts.append("Vulnerable operation: {}".format(", ".join(set(ops))))

    # Analyze the vulnerable lines for patterns
    for vline in vulnerable_lines[:20]:
        # Shift operations
        if '<<' in vline or '>>' in vline:
            trigger_parts.append("Vulnerable shift operation: `{}`".format(vline.strip()))
        # Allocation/realloc without size check
        if re.search(r'\brealloc\b|\bmalloc\b|\bcalloc\b', vline):
            trigger_parts.append("Vulnerable allocation: `{}`".format(vline.strip()))
        # Size/count comparisons
        if re.search(r'size|count|len|num|power|capacity', vline, re.IGNORECASE):
            trigger_parts.append("Size-related vulnerable code: `{}`".format(vline.strip()))

    # Analyze fix lines to understand what was added
    for fline in fix_lines[:20]:
        # Bounds checks added
        if re.search(r'if\s*\(.*(?:>|<|>=|<=|==).*\)', fline):
            trigger_parts.append("Fix added bounds check: `{}`".format(fline.strip()))
        # Type changes (e.g., int -> unsigned)
        if re.search(r'\bunsigned\b|\bsize_t\b|\buint\d+', fline):
            trigger_parts.append("Fix changed type to prevent overflow: `{}`".format(fline.strip()))
        # Overflow guards
        if re.search(r'overflow|MAX|LIMIT|saturate', fline, re.IGNORECASE):
            trigger_parts.append("Fix added overflow guard: `{}`".format(fline.strip()))

    result = {}
    if vulnerable_lines:
        result["vulnerable_lines"] = vulnerable_lines[:15]
    if fix_lines:
        result["fix_lines"] = fix_lines[:15]
    if affected_functions:
        result["affected_functions"] = affected_functions
    if trigger_parts:
        result["trigger_summary"] = trigger_parts
    if hunk_context:
        result["hunk_headers"] = hunk_context[:10]

    return result


# --------------- LLM-based trigger protocol synthesis ---------------

def synthesize_trigger_protocol(commit_messages, patch_diff, trigger_function_source,
                                entry_function_name, entry_function_source, description,
                                cache_dir=None, cve_id=""):
    """Ask the LLM to produce a concrete trigger protocol for the vulnerability.

    Bridges the gap between the abstract commit-message description ("what the
    vulnerability is") and the concrete API-call / input-pattern sequence needed
    to trigger it through the public entry point.

    Returns a dict with:
      - protocol_steps:  list[str]  — ordered steps the harness must perform
      - input_requirements: str     — what the fuzz input must contain
      - key_insight: str            — single-sentence summary of the trigger mechanism
    Returns {} on failure (LLM unavailable, bad response, etc.).
    """
    try:
        from llm_adapters.openai import run_openai_json
    except ImportError:
        return {}

    # Check cache
    if cache_dir and cve_id and entry_function_name:
        cache_dir = Path(cache_dir)
        cache_file = cache_dir / "{}.trigger_protocol.{}.json".format(
            cve_id, entry_function_name)
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if cached.get("protocol_steps"):
                    print("[trigger_protocol] Using cached protocol for {} / {}".format(
                        cve_id, entry_function_name))
                    return cached
            except Exception:
                pass

    # Load model configuration
    cfg_path = Path(__file__).resolve().parent / "config" / "llm.json"
    model = "gpt-4o"
    api_base = "https://api.openai.com/v1"
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        model = cfg.get("default", {}).get("model") or model
        api_base = cfg.get("default", {}).get("api_base") or api_base
    except Exception:
        pass

    # Build the synthesis prompt
    prompt_parts = [
        "You are a vulnerability-trigger specialist. Given a CVE fix commit, "
        "patch diff, and source code excerpts, determine the CONCRETE sequence "
        "of API calls and input patterns that a libFuzzer harness must use to "
        "trigger this vulnerability through the PUBLIC entry point.",
        "",
        "IMPORTANT RULES:",
        "- Focus on what the HARNESS must DO, not on explaining the vulnerability.",
        "- Every step must reference a real, public API function or a concrete "
        "input-data pattern (e.g. specific XML constructs, specific byte sequences, "
        "specific struct field values).",
        "- Do NOT suggest modifying library internals or accessing private state.",
        "- Be SPECIFIC: instead of 'provide specially crafted input', say exactly "
        "what the input must contain (e.g. 'include a DTD with <!ENTITY ...> "
        "declarations and reference them with &entity_name; in the body').",
        "",
        "Reply with ONLY a JSON object:",
        '{"protocol_steps": ["step 1...", "step 2...", ...], '
        '"input_requirements": "description of what the fuzz input must contain", '
        '"key_insight": "one-sentence summary of trigger mechanism"}',
        "",
    ]

    if description:
        prompt_parts.append("## CVE Description")
        prompt_parts.append(str(description)[:2000])
        prompt_parts.append("")

    if commit_messages:
        prompt_parts.append("## Fix Commit Message(s)")
        for msg in commit_messages[:3]:
            prompt_parts.append(str(msg)[:1500])
            prompt_parts.append("")

    if patch_diff:
        prompt_parts.append("## Fix Patch Diff")
        prompt_parts.append("```")
        prompt_parts.append(str(patch_diff)[:4000])
        prompt_parts.append("```")
        prompt_parts.append("")

    if entry_function_name:
        prompt_parts.append("## Public Entry Point: `{}`".format(entry_function_name))
    if entry_function_source:
        prompt_parts.append("```c")
        prompt_parts.append(str(entry_function_source)[:3000])
        prompt_parts.append("```")
        prompt_parts.append("")

    if trigger_function_source:
        prompt_parts.append("## Patch-Affected Trigger Function Source")
        prompt_parts.append("```c")
        prompt_parts.append(str(trigger_function_source)[:3000])
        prompt_parts.append("```")
        prompt_parts.append("")

    prompt_text = "\n".join(prompt_parts)

    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="rf_trigger_proto_"))
        prompt_file = tmp_dir / "prompt_trigger_protocol.md"
        out_file = tmp_dir / "response.json"
        prompt_file.write_text(prompt_text, encoding="utf-8")

        ok, msg = run_openai_json(
            prompt_path=prompt_file,
            out_path=out_file,
            model=model,
            api_base=api_base,
            max_retries=2,
        )
        if not ok:
            print("[trigger_protocol] LLM synthesis failed: {}".format(msg),
                  file=sys.stderr)
            return {}

        result = json.loads(out_file.read_text(encoding="utf-8"))

        # Validate structure
        steps = result.get("protocol_steps", [])
        if not isinstance(steps, list) or not steps:
            print("[trigger_protocol] LLM returned no protocol_steps",
                  file=sys.stderr)
            return {}

        protocol = {
            "protocol_steps": [str(s) for s in steps[:15]],
            "input_requirements": str(result.get("input_requirements", "")),
            "key_insight": str(result.get("key_insight", "")),
        }

        # Cache result
        if cache_dir and cve_id and entry_function_name:
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_file = cache_dir / "{}.trigger_protocol.{}.json".format(
                    cve_id, entry_function_name)
                cache_file.write_text(json.dumps(protocol, indent=2),
                                      encoding="utf-8")
            except Exception:
                pass

        print("[trigger_protocol] Synthesized {} protocol steps for {} / {}".format(
            len(protocol["protocol_steps"]), cve_id, entry_function_name))
        return protocol

    except Exception as exc:
        print("[trigger_protocol] LLM synthesis error: {}".format(exc),
              file=sys.stderr)
        return {}


# --------------- Multi-source function extraction ---------------

def _extract_function_from_all_descriptions(enrichment, enriched,
                                             known_functions=None):
    """Try extracting the affected function from every available description source.

    Priority: NVD description > OSV details > OSV summary > GitHub description
    > GitHub summary.  Returns the first successful extraction or empty string.

    If *known_functions* is provided, all sources are scanned and the
    candidate that appears in the project's actual function set is preferred
    over a textually-earlier candidate that does not.
    """
    sources = [
        enriched.get("description", ""),
        enrichment.get("description", ""),
        enrichment.get("osv_details", ""),
        enrichment.get("osv_summary", ""),
        enrichment.get("gh_description", ""),
        enrichment.get("gh_summary", ""),
    ]
    seen = set()
    all_candidates = []  # (func_name, source_priority)
    for priority, text in enumerate(sources):
        if not text or text in seen:
            continue
        seen.add(text)
        func = _extract_function_from_description(text)
        if func:
            all_candidates.append((func, priority))

    if not all_candidates:
        return ""

    # Without cross-validation, return the highest-priority (earliest) match.
    if not known_functions:
        return all_candidates[0][0]

    # Prefer a candidate that actually exists in the project's codebase.
    for func, _ in all_candidates:
        if func in known_functions:
            return func
    # No candidate matched the codebase — return the best textual match.
    return all_candidates[0][0]


def _extract_function_from_commit_messages(patch_diffs):
    """Extract the affected function name from commit Subject lines in patches.

    Git format-patch text contains ``Subject: ...`` headers describing the
    change.  Security fixes commonly mention the function, e.g.:
    - "Fix use-after-free in doContent"
    - "xmlparse: fix heap overflow"
    - "Fix bug in foo_bar()"

    Prioritizes subjects mentioning CVE IDs or security keywords.
    """
    if not patch_diffs:
        return ""
    subjects = []
    for pd in patch_diffs:
        for line in (pd or "").split("\n"):
            if line.startswith("Subject: "):
                # Strip the [PATCH n/m] prefix if present
                subj = re.sub(r'^Subject:\s*(?:\[.*?\]\s*)*', '', line)
                subjects.append(subj.strip())

    # Reorder subjects: prioritize those mentioning CVE or security keywords
    _SEC_KW = re.compile(r'CVE-|security|vulnerab|overflow|use.after.free|'
                         r'out.of.bounds|heap|uaf|double.free|injection|bypass',
                         re.IGNORECASE)
    sec_subjects = [s for s in subjects if _SEC_KW.search(s)]
    other_subjects = [s for s in subjects if not _SEC_KW.search(s)]
    ordered_subjects = sec_subjects + other_subjects

    for subj in ordered_subjects:
        # Try the generic description extractor first (handles "in FUNC function" etc.)
        func = _extract_function_from_description(subj)
        if func:
            return func

        # Pattern: "FUNC: fix ..." (common prefix style)
        m = re.match(r'^([a-zA-Z_]\w+)\s*:', subj)
        if m and _is_plausible_c_function(m.group(1)):
            return m.group(1)

        # Pattern: "Fix ... in FUNC" (trailing function)
        m = re.search(r'\b(?:fix|patch|resolve|address)\b.*?\bin\s+([a-zA-Z_]\w+)\s*$',
                       subj, re.IGNORECASE)
        if m and _is_plausible_c_function(m.group(1)):
            return m.group(1)

        # Pattern: "FUNC()" call syntax anywhere in subject
        m = re.search(r'\b([a-zA-Z_]\w+)\(\)', subj)
        if m and _is_plausible_c_function(m.group(1)):
            return m.group(1)

    return ""


def _rank_function_candidates(candidates, description="", commit_subjects=None):
    """Score and rank multiple function-name candidates.

    Returns the best candidate or empty string if none pass validation.
    """
    if not candidates:
        return ""
    commit_subjects = commit_subjects or []
    desc_lower = (description or "").lower()
    subj_text = " ".join(commit_subjects).lower()

    scored = []
    for name in candidates:
        if not _is_plausible_c_function(name):
            continue
        score = 0
        name_lower = name.lower()
        # Mentioned in CVE description
        if name_lower in desc_lower:
            score += 10
        # Mentioned in commit subject
        if name_lower in subj_text:
            score += 8
        # Looks like a real library function (has underscore or mixed case)
        if '_' in name or (name != name.lower() and name != name.upper()):
            score += 2
        # Penalize test/mock functions
        if re.search(r'test|spec|mock|stub|fake|dummy', name_lower):
            score -= 5
        scored.append((score, name))

    if not scored:
        return ""
    scored.sort(key=lambda x: (-x[0], x[1]))  # highest score first, stable
    return scored[0][1]


def _extract_function_from_patch_hunks(patch_diffs, description="", affected_file=""):
    """Extract the affected function from patch hunk headers.

    Uses ``extract_trigger_condition()`` to parse ``@@ ... @@ func(`` headers,
    then ranks candidates by cross-referencing with the CVE description.

    If *affected_file* is known, prioritizes functions from sub-patches that
    touch that file.
    """
    if not patch_diffs:
        return ""

    # Collect functions, separating those from affected-file sub-patches
    file_funcs = []   # functions from sub-patches touching affected_file
    all_funcs = []
    affected_base = os.path.basename(affected_file).lower() if affected_file else ""
    for pd in patch_diffs:
        if affected_base:
            # Parse line-by-line to track which file each hunk belongs to
            current_file = ""
            for line in (pd or "").split("\n"):
                if line.startswith("+++ b/"):
                    path = line[6:].strip()
                    current_file = (path.rsplit("/", 1)[-1] if "/" in path else path).lower()
                elif line.startswith("@@"):
                    m = re.search(r'@@[^@]+@@\s*(?:\w+\s+)*(\w+)\s*\(', line)
                    if m:
                        fn = m.group(1)
                        if not _is_plausible_c_function(fn):
                            continue
                        if current_file == affected_base:
                            if fn not in file_funcs:
                                file_funcs.append(fn)
                        else:
                            if fn not in all_funcs:
                                all_funcs.append(fn)
        else:
            tc = extract_trigger_condition(pd, description)
            for fn in tc.get("affected_functions", []):
                if fn not in all_funcs:
                    all_funcs.append(fn)

    # Prefer functions from the affected file's sub-patches
    # Prefer functions from the affected file's sub-patches.
    # If we know the affected file but found NO functions from its patches,
    # return "" rather than falling back to unrelated files (avoids false
    # positives; allows the LLM fallback to run).
    if affected_base and not file_funcs:
        return ""
    candidates = file_funcs if file_funcs else all_funcs
    if not candidates:
        return ""
    if len(candidates) == 1:
        return candidates[0] if _is_plausible_c_function(candidates[0]) else ""

    # Collect commit subjects for ranking context
    subjects = []
    for pd in patch_diffs:
        for line in (pd or "").split("\n"):
            if line.startswith("Subject: "):
                subjects.append(re.sub(r'^Subject:\s*(?:\[.*?\]\s*)*', '', line).strip())

    return _rank_function_candidates(candidates, description, subjects)


# URL patterns for bug trackers and issue pages worth scraping
_BUG_TRACKER_RE = re.compile(
    r'bugzilla|/issues?/|/bugs?/|crbug\.com|oss-fuzz\.com|bugs\.chromium'
    r'|gitlab\.com/.*/issues|sourceware\.org|savannah',
    re.IGNORECASE
)


def _extract_function_from_references(enrichment):
    """Try to extract the affected function from NVD/OSV reference URLs.

    Fetches bug-tracker / issue pages and applies function extraction patterns
    to their text content.  Limited to 3 pages, 10 KB each, 10 s timeout.
    """
    urls = []
    for ref in enrichment.get("references", []):
        url = ref.get("url", "")
        if url and _BUG_TRACKER_RE.search(url):
            urls.append(url)
    for ref in enrichment.get("osv_references", []):
        url = ref.get("url", "")
        if url and _BUG_TRACKER_RE.search(url):
            urls.append(url)

    # Deduplicate, limit to 3
    seen = set()
    unique_urls = []
    for u in urls:
        n = u.rstrip("/")
        if n not in seen:
            seen.add(n)
            unique_urls.append(u)
        if len(unique_urls) >= 3:
            break

    for url in unique_urls:
        text = _get_text(url, timeout=10)
        if not text:
            continue
        # Limit to first 10 KB to avoid processing huge pages
        text = text[:10240]
        # Strip HTML tags to get plain text for pattern matching
        plain = re.sub(r'<[^>]+>', ' ', text)
        func = _extract_function_from_description(plain)
        if func:
            print("[enrichment] Extracted function '{}' from reference: {}".format(func, url))
            return func
    return ""


def _extract_function_via_llm(enriched, enrichment):
    """Last-resort: ask the LLM to identify the vulnerable function.

    Only called when all deterministic methods fail.  Uses the project's
    existing LLM adapter with a minimal focused prompt.
    """
    try:
        from llm_adapters.openai import run_openai_json
    except ImportError:
        return ""

    # Load model configuration
    cfg_path = Path(__file__).resolve().parent / "config" / "llm.json"
    model = "gpt-4o"
    api_base = "https://api.openai.com/v1"
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        model = cfg.get("default", {}).get("model") or model
        api_base = cfg.get("default", {}).get("api_base") or api_base
    except Exception:
        pass

    # Build the prompt — concise to minimise cost
    desc = enriched.get("description", "") or ""
    osv_details = enrichment.get("osv_details", "") or ""
    patch_excerpt = ""
    for pd in enrichment.get("patch_diffs", []):
        if pd:
            patch_excerpt = pd[:4000]
            break

    prompt_text = (
        "Given the following CVE information, identify the single C or C++ "
        "function that contains the vulnerability (the \"sink\" function "
        "where the bug manifests, NOT a wrapper or caller).\n\n"
        "Reply with ONLY a JSON object: {\"function_name\": \"<name>\"}\n"
        "If you cannot determine the function, reply: {\"function_name\": \"\"}\n\n"
    )
    if desc:
        prompt_text += "## CVE Description\n" + desc[:2000] + "\n\n"
    if osv_details and osv_details != desc:
        prompt_text += "## Additional Details\n" + osv_details[:2000] + "\n\n"
    if patch_excerpt:
        prompt_text += "## Fix Patch (excerpt)\n```\n" + patch_excerpt + "\n```\n"

    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="rf_llm_func_"))
        prompt_file = tmp_dir / "prompt_func_extract.md"
        out_file = tmp_dir / "response.json"
        prompt_file.write_text(prompt_text, encoding="utf-8")

        ok, msg = run_openai_json(
            prompt_path=prompt_file,
            out_path=out_file,
            model=model,
            api_base=api_base,
            max_retries=2,
        )
        if not ok:
            print("[enrichment] LLM function extraction failed: {}".format(msg),
                  file=sys.stderr)
            return ""

        result = json.loads(out_file.read_text(encoding="utf-8"))
        func = result.get("function_name", "").strip()
        if func and _is_plausible_c_function(func):
            print("[enrichment] LLM identified function: {}".format(func))
            return func
        return ""
    except Exception as exc:
        print("[enrichment] LLM function extraction error: {}".format(exc),
              file=sys.stderr)
        return ""


def _derive_affected_function(enriched, enrichment, known_functions=None):
    """Multi-source cascading extraction of the affected function name.

    Tries progressively more expensive sources and returns the first match:
    1. All available descriptions (regex patterns)
    2. Commit message Subject lines
    3. Patch hunk headers (with cross-reference ranking)
    4. Bug-tracker reference URLs
    5. LLM extraction (last resort)

    If *known_functions* (a set of function names from the project's call
    graph) is provided, candidates that appear in the project are boosted
    so that textually plausible names that don't exist in the codebase are
    less likely to win.
    """
    desc = enriched.get("description", "")
    affected_file = enriched.get("affected-file", "")
    patch_diffs = enrichment.get("patch_diffs", []) or []

    # 0. Patch hunk headers FIRST when patches exist AND the candidate is
    # corroborated by the CVE description (or by the project's call graph).
    # Hunk-header function names from the security-fix commit are ground
    # truth for *what was changed*, but a multi-file fix may patch helper
    # functions whose names don't match the actual crash site.  Requiring
    # corroboration prevents us from preferring a helper over the API
    # surface that the description points at.
    if patch_diffs:
        hunk_func = _extract_function_from_patch_hunks(
            patch_diffs, desc, affected_file)
        if hunk_func and _is_plausible_c_function(hunk_func):
            corroborated = False
            if known_functions and hunk_func in known_functions:
                corroborated = True
            elif desc and re.search(r'\b' + re.escape(hunk_func) + r'\b', desc):
                corroborated = True
            if corroborated:
                print("[enrichment] Auto-derived affected-function from patch hunks: {}".format(hunk_func))
                return hunk_func

    # 1. Try all description sources
    func = _extract_function_from_all_descriptions(enrichment, enriched,
                                                    known_functions=known_functions)
    if func:
        print("[enrichment] Auto-derived affected-function from description: {}".format(func))
        return func

    # 2. Try commit message subjects
    func = _extract_function_from_commit_messages(patch_diffs)
    if func:
        print("[enrichment] Auto-derived affected-function from commit message: {}".format(func))
        return func

    # 3. Patch hunk headers (fallback if the above didn't pass the
    # known-functions check; runs again here without that constraint).
    func = _extract_function_from_patch_hunks(patch_diffs, desc, affected_file)
    if func:
        print("[enrichment] Auto-derived affected-function from patch hunks: {}".format(func))
        return func

    # 4. Try bug-tracker reference pages
    func = _extract_function_from_references(enrichment)
    if func:
        print("[enrichment] Auto-derived affected-function from reference URL: {}".format(func))
        return func

    # 5. Last resort: ask the LLM
    func = _extract_function_via_llm(enriched, enrichment)
    if func:
        print("[enrichment] Auto-derived affected-function via LLM: {}".format(func))
        return func

    return ""


# --------------- CLI for standalone testing ---------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Enrich CVE entry with public database information"
    )
    parser.add_argument("--vulns", required=True, help="Path to vulnerabilities.json")
    parser.add_argument("--cve-id", required=True, help="CVE ID to enrich")
    parser.add_argument("--out", help="Output file for enriched entry (default: stdout)")
    parser.add_argument("--cache-dir", help="Directory for caching API responses")
    args = parser.parse_args()

    vulns_data = json.loads(Path(args.vulns).read_text(encoding="utf-8"))
    vulns = vulns_data.get("vulnerabilities", vulns_data.get("vulns", []))
    target = next((v for v in vulns if v.get("cve-id") == args.cve_id), None)

    if not target:
        print("CVE {} not found in {}".format(args.cve_id, args.vulns), file=sys.stderr)
        sys.exit(1)

    cache_path = Path(args.cache_dir) if args.cache_dir else None
    enriched = enrich_vulnerability(target, cache_dir=cache_path)

    output = json.dumps(enriched, indent=2)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print("Enriched entry written to {}".format(args.out))
    else:
        print(output)
