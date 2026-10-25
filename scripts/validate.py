#!/usr/bin/env python3
"""Validate advisory files.

    validate.py [--online] FILE...

Offline checks mirror what vuln-watch accepts (src/sources/advisory.rs) plus the
rules in CLAUDE.md. With --online, every reference URL must answer 2xx, the quote of
each reference must appear in its page, and every CVE id must exist at cve.org.
"""

import datetime as dt
import html
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

TOP = {
    "id": True, "revision": True, "status": True, "published": True, "updated": False,
    "expires": True, "severity": True, "confidence": True, "title": True, "summary": True,
    "affects": False, "cves": False, "actions": False, "references": True,
}
AFFECTS = {"name", "keywords", "packages", "fixed_versions", "deb"}
DEB = {"package", "fixed_version", "release"}
REFERENCE = {"url", "kind", "title", "quote"}
ID_RE = re.compile(r"^VWA-\d{4}-\d{4}-[a-z0-9]+(-[a-z0-9]+)*$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_DAYS = 90
UA = "vuln-watch-advisories-validator (+https://github.com/Matuyuhi/vuln-watch)"


def check(path: Path, online: bool) -> list[str]:
    errs: list[str] = []
    try:
        a = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return [f"not valid TOML: {e}"]

    for k in a:
        if k not in TOP:
            errs.append(f"unknown key `{k}`")
    for k, required in TOP.items():
        if required and k not in a:
            errs.append(f"missing `{k}`")
    if errs:
        return errs

    if a["id"] != path.stem:
        errs.append(f"id `{a['id']}` must equal the file name `{path.stem}`")
    if not ID_RE.match(a["id"]):
        errs.append("id must look like VWA-2026-1025-some-slug")
    if not isinstance(a["revision"], int) or a["revision"] < 1:
        errs.append("revision must be an integer >= 1")
    if a["status"] not in ("active", "resolved", "withdrawn"):
        errs.append("status must be active | resolved | withdrawn")
    if a["severity"] not in ("critical", "high", "medium", "low"):
        errs.append("severity must be critical | high | medium | low")
    if a["confidence"] not in ("confirmed", "likely", "unverified"):
        errs.append("confidence must be confirmed | likely | unverified")
    for k in ("title", "summary"):
        if not isinstance(a[k], str) or not a[k].strip():
            errs.append(f"`{k}` must be a non-empty string")

    dates = {}
    for k in ("published", "updated", "expires"):
        if k in a:
            if type(a[k]) is not dt.date:
                errs.append(f"`{k}` must be a bare date such as 2026-10-25")
            else:
                dates[k] = a[k]
    if "published" in dates and "expires" in dates:
        start = dates.get("updated", dates["published"])
        if dates["expires"] < start:
            errs.append("expires is before published/updated")
        if (dates["expires"] - start).days > MAX_DAYS:
            errs.append(f"expires is more than {MAX_DAYS} days after published/updated")

    for i, af in enumerate(a.get("affects", [])):
        for k in af:
            if k not in AFFECTS:
                errs.append(f"affects[{i}]: unknown key `{k}`")
        if not str(af.get("name", "")).strip():
            errs.append(f"affects[{i}]: missing name")
        for j, d in enumerate(af.get("deb", [])):
            for k in d:
                if k not in DEB:
                    errs.append(f"affects[{i}].deb[{j}]: unknown key `{k}`")
            if not d.get("package") or not d.get("fixed_version"):
                errs.append(f"affects[{i}].deb[{j}]: needs package and fixed_version")

    for c in a.get("cves", []):
        if not CVE_RE.match(str(c)):
            errs.append(f"`{c}` is not a CVE id")

    refs = a["references"]
    if not refs:
        errs.append("at least one reference is required")
    for i, r in enumerate(refs):
        for k in r:
            if k not in REFERENCE:
                errs.append(f"references[{i}]: unknown key `{k}`")
        if not str(r.get("url", "")).startswith("https://"):
            errs.append(f"references[{i}]: url must be https")
        if r.get("kind") not in ("primary", "secondary"):
            errs.append(f"references[{i}]: kind must be primary | secondary")
        if r.get("kind") == "primary" and not str(r.get("quote", "")).strip():
            errs.append(f"references[{i}]: a primary reference needs a quote")
    has_primary = any(r.get("kind") == "primary" for r in refs)
    if a["confidence"] != "unverified" and not has_primary:
        errs.append("confidence above unverified needs a primary reference")
    if not has_primary and a["severity"] in ("critical", "high"):
        errs.append("without a primary reference severity must be medium or low")

    if online and not errs:
        errs += check_online(a)
    return errs


def fetch(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read(8 * 1024 * 1024)
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.status, body.decode(charset, errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def normalize(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = text.replace("’", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", text).strip().lower()


def check_online(a: dict) -> list[str]:
    errs = []
    for i, r in enumerate(a["references"]):
        try:
            status, body = fetch(r["url"])
        except Exception as e:  # noqa: BLE001
            errs.append(f"references[{i}]: {r['url']} failed: {e}")
            continue
        if not 200 <= status < 300:
            errs.append(f"references[{i}]: {r['url']} returned HTTP {status}")
            continue
        quote = str(r.get("quote", "")).strip()
        if quote and normalize(quote) not in normalize(body):
            errs.append(f"references[{i}]: quote not found in {r['url']}")
    for c in a.get("cves", []):
        try:
            status, _ = fetch(f"https://cveawg.mitre.org/api/cve/{c}")
        except Exception as e:  # noqa: BLE001
            errs.append(f"{c}: lookup failed: {e}")
            continue
        if status != 200:
            errs.append(f"{c}: not found at cve.org (HTTP {status})")
    return errs


def main(argv: list[str]) -> int:
    online = "--online" in argv
    files = [Path(p) for p in argv if p != "--online"]
    failed = False
    for f in files:
        for e in check(f, online):
            failed = True
            print(f"::error file={f}::{e}")
            print(f"{f}: {e}", file=sys.stderr)
    if not failed:
        print(f"{len(files)} file(s) ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
