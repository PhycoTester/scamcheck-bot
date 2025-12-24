import os
import re
import json
import time
from typing import List, Dict, Any
from urllib.parse import urlparse

import requests
import tldextract


# -------------------------
# Defaults / configuration
# -------------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    "autoscan_enabled": True,
    "autoscan_channels_allowlist": [],
    "autoscan_channels_blocklist": [],
    "max_urls_per_message": 3,
    "cooldown_seconds_per_user": 10,

    "blocked_domains": ["youtube.com", "www.youtube.com", "youtu.be"],
    "shortener_domains": ["tinyurl.com", "bit.ly", "t.co", "is.gd", "cutt.ly", "rb.gy", "lnkd.in"],
    "high_abuse_suffixes": ["herokuapp.com", "vercel.app", "netlify.app", "github.io", "pages.dev", "glitch.me"],

    "enable_virustotal": False,
    "enable_urlscan": False,

    # caching
    "url_cache_ttl_seconds": 300,
    "host_cache_max": 2000,
}

HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "").strip()

_URL_REGEX = re.compile(r"(https?://[^\s<>()]+|www\.[^\s<>()]+)", re.IGNORECASE)

SCAM_PATTERNS = [
    (re.compile(r"\b(reply\s+yes\s+to\s+proceed)\b", re.I), 25, "Reply-YES flow"),
    (re.compile(r"\b(pre[-\s]?offer\s+letter)\b", re.I), 15, "Pre-offer letter wording"),
    (re.compile(r"\b(check|cheque)\b.*\b(equipment|software|supplies|purchase)\b", re.I), 45, "Check-to-buy-equipment"),
    (re.compile(r"\burgent|eod|immediately|act\s+fast|within\s+24\s+hours\b", re.I), 10, "Artificial urgency"),
    (re.compile(r"\btelegram|whatsapp|signal\b", re.I), 15, "Moves to chat apps"),
    (re.compile(r"\bkindly\b", re.I), 5, "Scam phrasing (‘kindly’)"),
]


# -------------------------
# Small caches (in-memory)
# -------------------------
_URL_CACHE: Dict[str, Any] = {}      # url -> (expires_at, result_dict)
_HOST_CACHE: Dict[str, Any] = {}     # host -> domain_info dict


def load_config(path: str = "config.json") -> Dict[str, Any]:
    """
    Loads config.json if present; otherwise returns defaults.
    If file exists but is invalid, falls back to defaults.
    """
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path, "r", encoding="utf-8") as f:
            disk = json.load(f) or {}
            if isinstance(disk, dict):
                cfg.update(disk)
    except FileNotFoundError:
        pass
    except Exception:
        # Corrupt config: fall back to defaults.
        pass
    return cfg


def normalize_url(url: str) -> str:
    url = (url or "").strip().strip("<>").strip()
    if not url:
        return ""
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls: List[str] = []
    for m in _URL_REGEX.finditer(text):
        u = normalize_url(m.group(0))
        # strip common trailing punctuation
        u = u.rstrip(").,!?\"'")
        if u:
            urls.append(u)

    # de-dup preserve order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def label(verdict: str) -> str:
    return {
        "LOW": "🟢 SAFE",
        "MEDIUM": "🟡 SUSPICIOUS",
        "HIGH": "🔴 SCAM LIKELY",
        "INFO": "ℹ️ INFO",
    }.get(verdict, verdict)


def verdict_from_score(score: int) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _cache_get(url: str) -> Any:
    item = _URL_CACHE.get(url)
    if not item:
        return None
    exp, val = item
    if time.monotonic() > exp:
        _URL_CACHE.pop(url, None)
        return None
    return val


def _cache_set(url: str, val: dict, ttl_seconds: int) -> None:
    _URL_CACHE[url] = (time.monotonic() + max(5, int(ttl_seconds)), val)


def domain_info(url: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    p = urlparse(url)
    host = (p.hostname or "").lower()

    cached = _HOST_CACHE.get(host)
    if cached:
        return cached

    ext = tldextract.extract(host)
    reg_domain = ".".join([x for x in [ext.domain, ext.suffix] if x]).lower()
    info = {
        "host": host,
        "registered_domain": reg_domain,
        "suffix": (ext.suffix or "").lower(),
    }

    # Bound host cache size
    max_hosts = int(cfg.get("host_cache_max", DEFAULT_CONFIG["host_cache_max"]))
    if len(_HOST_CACHE) >= max_hosts:
        # crude eviction: clear (simple & safe)
        _HOST_CACHE.clear()
    _HOST_CACHE[host] = info
    return info


def safe_head_or_get(session: requests.Session, url: str) -> requests.Response:
    resp = session.head(url, allow_redirects=False, timeout=HTTP_TIMEOUT)
    if resp.status_code in (403, 405):
        resp = session.get(url, allow_redirects=False, timeout=HTTP_TIMEOUT, stream=True)
    return resp


def expand_redirects(url: str, max_hops: int = MAX_REDIRECTS) -> Dict[str, Any]:
    url = normalize_url(url)
    if not url:
        return {"ok": False, "error": "Empty URL"}

    session = requests.Session()
    current = url
    chain = [current]

    try:
        for _ in range(max_hops):
            resp = safe_head_or_get(session, current)
            if resp.is_redirect:
                loc = resp.headers.get("Location")
                if not loc:
                    break
                current = requests.compat.urljoin(current, loc)
                chain.append(current)
                continue
            break
        return {"ok": True, "input": url, "final": current, "chain": chain}
    except requests.RequestException as e:
        return {"ok": False, "input": url, "error": str(e)}


def expand_shortlink_safely(url: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Only follows redirects while still on a known shortener domain.
    Stops as soon as it leaves shortener space (less invasive).
    """
    url = normalize_url(url)
    if not url:
        return {"ok": False, "error": "Empty URL"}

    shorteners = set([d.lower() for d in cfg.get("shortener_domains", [])])
    session = requests.Session()
    current = url
    chain = [current]

    try:
        for _ in range(MAX_REDIRECTS):
            host = (urlparse(current).hostname or "").lower()
            if host not in shorteners:
                break

            resp = safe_head_or_get(session, current)
            if resp.is_redirect:
                loc = resp.headers.get("Location")
                if not loc:
                    break
                current = requests.compat.urljoin(current, loc)
                chain.append(current)
                continue
            break

        return {"ok": True, "input": url, "final": current, "chain": chain, "shortlink_only": True}
    except requests.RequestException as e:
        return {"ok": False, "input": url, "error": str(e), "shortlink_only": True}


def score_email_text(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    score = 0
    hits = []
    for rx, pts, label_ in SCAM_PATTERNS:
        if rx.search(text):
            score += pts
            hits.append(label_)
    return {"score": score, "verdict": verdict_from_score(score), "hits": hits}


def vt_url_stats(url: str) -> Dict[str, Any]:
    if not VT_KEY:
        return {"enabled": False}

    headers = {"x-apikey": VT_KEY}
    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=HTTP_TIMEOUT,
        )
        if submit.status_code not in (200, 201):
            return {"enabled": True, "error": f"VT submit failed: {submit.status_code}"}

        analysis_id = submit.json().get("data", {}).get("id")
        if not analysis_id:
            return {"enabled": True, "error": "VT missing analysis id"}

        time.sleep(2)

        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )
        if analysis.status_code != 200:
            return {"enabled": True, "error": f"VT analysis fetch failed: {analysis.status_code}"}

        stats = analysis.json().get("data", {}).get("attributes", {}).get("stats", {})
        return {"enabled": True, "stats": stats}
    except requests.RequestException as e:
        return {"enabled": True, "error": str(e)}


def urlscan_submit(url: str) -> Dict[str, Any]:
    if not URLSCAN_KEY:
        return {"enabled": False}

    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    body = {"url": url, "visibility": "private"}

    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            data=json.dumps(body),
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code not in (200, 201):
            return {"enabled": True, "error": f"urlscan submit failed: {resp.status_code}"}
        j = resp.json()
        return {"enabled": True, "result": j.get("result"), "uuid": j.get("uuid")}
    except requests.RequestException as e:
        return {"enabled": True, "error": str(e)}


def score_url(url: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    url = normalize_url(url)
    if not url:
        return {"ok": False, "error": "Empty URL"}

    # cache
    cached = _cache_get(url)
    if cached:
        return cached

    ttl = int(cfg.get("url_cache_ttl_seconds", DEFAULT_CONFIG["url_cache_ttl_seconds"]))

    host = (urlparse(url).hostname or "").lower()
    blocked = set([d.lower() for d in cfg.get("blocked_domains", [])])

    if host in blocked:
        result = {
            "ok": True,
            "input": url,
            "final": url,
            "chain": [url],
            "domain": domain_info(url, cfg),
            "score": 0,
            "verdict": "INFO",
            "reasons": ["Domain blocked by local network (not analyzed)"],
            "virustotal": {"enabled": False},
            "urlscan": {"enabled": False},
        }
        _cache_set(url, result, ttl)
        return result

    shorteners = set([d.lower() for d in cfg.get("shortener_domains", [])])
    if host in shorteners:
        exp = expand_shortlink_safely(url, cfg)
    else:
        exp = expand_redirects(url)

    if not exp.get("ok"):
        return {"ok": False, "error": exp.get("error", "Unknown error")}

    final = exp["final"]
    info = domain_info(final, cfg)

    high_abuse_suffixes = tuple([s.lower() for s in cfg.get("high_abuse_suffixes", [])])

    score = 0
    reasons = []

    if len(exp.get("chain", [])) > 1:
        score += 10
        reasons.append("Redirect chain")

    if host in shorteners:
        score += 15
        reasons.append("Shortened link")

    if (info["host"] or "").endswith(high_abuse_suffixes):
        score += 10
        reasons.append("High-abuse hosting (caution)")

    vt = {"enabled": False}
    us = {"enabled": False}

    if bool(cfg.get("enable_virustotal")) and VT_KEY:
        vt = vt_url_stats(final)
        if vt.get("enabled") and vt.get("stats"):
            mal = int(vt["stats"].get("malicious", 0))
            susp = int(vt["stats"].get("suspicious", 0))
            if mal > 0:
                score += 50
                reasons.append(f"VirusTotal: {mal} malicious")
            elif susp > 0:
                score += 25
                reasons.append(f"VirusTotal: {susp} suspicious")

    if bool(cfg.get("enable_urlscan")) and URLSCAN_KEY:
        us = urlscan_submit(final)

    verdict = verdict_from_score(score)
    result = {
        "ok": True,
        "input": exp["input"],
        "final": final,
        "chain": exp["chain"],
        "domain": info,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "virustotal": vt,
        "urlscan": us,
    }
    _cache_set(url, result, ttl)
    return result
