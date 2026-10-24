#!/usr/bin/env python3
"""Turn "## [Unreleased]" in CHANGELOG.md into a dated release section.

    scripts/changelog-release.py VERSION DATE REPO_URL PREV_TAG [CHANGELOG]

For a pre-release (1.2.0-rc.1) the Unreleased entries become the new section.

For a final release (1.2.0), the sections of its pre-releases (1.2.0-rc.*) are
folded in as well: their entries are merged with Unreleased by category into the
1.2.0 section, and the pre-release sections and links are removed. The 1.2.0
section then lists everything since the previous final release, and Unreleased
may be empty when nothing changed after the last pre-release.

PREV_TAG is the tag the new version is compared with (empty for the first
release). Fails when there is nothing to release.

    scripts/changelog-release.py --self-test
"""

import re
import sys

CATEGORY_ORDER = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"]
SECTION_RE = re.compile(r"^## \[([^\]]+)\]")
LINK_RE = re.compile(r"^\[([^\]]+)\]: ")


def strip_blank(lines):
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    return lines


def parse(text):
    """Split into (preamble, [(version, heading, body_lines)], link_lines)."""
    preamble, sections, links = [], [], []
    current = None
    for line in text.splitlines():
        m = SECTION_RE.match(line)
        if m:
            current = (m.group(1), line, [])
            sections.append(current)
        elif LINK_RE.match(line):
            links.append(line)
        elif current is None:
            preamble.append(line)
        else:
            current[2].append(line)
    return strip_blank(preamble), sections, links


def categories(body):
    """Ordered {category: lines}; text before the first ### goes under ""."""
    out, name = {}, ""
    for line in body:
        if line.startswith("### "):
            name = line[4:].strip()
            out.setdefault(name, [])
        else:
            out.setdefault(name, []).append(line)
    return {k: strip_blank(v) for k, v in out.items() if strip_blank(v)}


def merge(bodies):
    """Merge bodies by category, keeping the order of `bodies` within each."""
    merged = {}
    for body in bodies:
        for name, lines in categories(body).items():
            merged.setdefault(name, []).extend(lines)
    order = [""] + CATEGORY_ORDER
    names = [n for n in order if n in merged]
    names += [n for n in merged if n not in names]
    out = []
    for name in names:
        if out:
            out.append("")
        if name:
            out += [f"### {name}", ""]
        out += merged[name]
    return out


def is_prerelease_of(candidate, version):
    return candidate.startswith(version + "-")


def release(text, version, date, url, prev_tag):
    tag = f"v{version}"
    final = "-" not in version
    preamble, sections, links = parse(text)

    if not any(v == "Unreleased" for v, _, _ in sections):
        raise SystemExit('error: CHANGELOG.md has no "## [Unreleased]" section')
    if any(v == version for v, _, _ in sections):
        raise SystemExit(f"error: CHANGELOG.md already has a section for {version}")

    unreleased = next(body for v, _, body in sections if v == "Unreleased")
    folded = [
        (v, body) for v, _, body in sections if final and is_prerelease_of(v, version)
    ]
    body = merge([unreleased] + [b for _, b in folded])
    if not body:
        raise SystemExit('error: nothing listed under "## [Unreleased]" in CHANGELOG.md')
    folded_versions = {v for v, _ in folded}

    out = preamble + ["", "## [Unreleased]", "", f"## [{version}] - {date}", ""] + body
    for v, heading, section_body in sections:
        if v == "Unreleased" or v in folded_versions:
            continue
        out += ["", heading] + [""] + strip_blank(section_body)

    new_links = [f"[Unreleased]: {url}/compare/{tag}...HEAD"]
    if prev_tag:
        new_links.append(f"[{version}]: {url}/compare/{prev_tag}...{tag}")
    else:
        new_links.append(f"[{version}]: {url}/releases/tag/{tag}")
    for line in links:
        name = LINK_RE.match(line).group(1)
        if name in ("Unreleased", version) or name in folded_versions:
            continue
        new_links.append(line)
    out += [""] + new_links
    return "\n".join(out) + "\n", sorted(folded_versions)


SAMPLE = """# Changelog

Intro.

## [Unreleased]

### Fixed

- unreleased fix

### Changed

- unreleased change

## [1.1.0-rc.2] - 2026-10-25

### Fixed

- rc2 fix

## [1.1.0-rc.1] - 2026-10-24

### Added

- rc1 feature
  continued line

### Fixed

- rc1 fix

## [1.0.3] - 2026-10-24

### Fixed

- old fix

[Unreleased]: https://x/compare/v1.1.0-rc.2...HEAD
[1.1.0-rc.2]: https://x/compare/v1.1.0-rc.1...v1.1.0-rc.2
[1.1.0-rc.1]: https://x/compare/v1.0.3...v1.1.0-rc.1
[1.0.3]: https://x/compare/v1.0.2...v1.0.3
"""


def self_test():
    out, folded = release(SAMPLE, "1.1.0", "2026-10-26", "https://x", "v1.0.3")
    assert folded == ["1.1.0-rc.1", "1.1.0-rc.2"], folded
    expected_section = """## [Unreleased]

## [1.1.0] - 2026-10-26

### Added

- rc1 feature
  continued line

### Changed

- unreleased change

### Fixed

- unreleased fix
- rc2 fix
- rc1 fix

## [1.0.3] - 2026-10-24"""
    assert expected_section in out, out
    assert "rc.1]" not in out.split("[Unreleased]:")[0], out
    assert out.endswith(
        "[Unreleased]: https://x/compare/v1.1.0...HEAD\n"
        "[1.1.0]: https://x/compare/v1.0.3...v1.1.0\n"
        "[1.0.3]: https://x/compare/v1.0.2...v1.0.3\n"
    ), out
    assert out.startswith("# Changelog\n\nIntro.\n\n## [Unreleased]\n"), out

    # Final release with nothing after the last pre-release.
    empty = SAMPLE.replace(
        "### Fixed\n\n- unreleased fix\n\n### Changed\n\n- unreleased change\n\n", ""
    )
    out, folded = release(empty, "1.1.0", "2026-10-26", "https://x", "v1.0.3")
    assert len(folded) == 2 and "- rc2 fix\n- rc1 fix" in out, out

    # A pre-release only takes Unreleased and keeps earlier pre-releases.
    out, folded = release(SAMPLE, "1.1.0-rc.3", "2026-10-26", "https://x", "v1.1.0-rc.2")
    assert folded == [] and "## [1.1.0-rc.2] - 2026-10-25" in out, out
    assert "[1.1.0-rc.3]: https://x/compare/v1.1.0-rc.2...v1.1.0-rc.3" in out, out

    # Nothing to release.
    try:
        release(empty, "1.1.0-rc.3", "2026-10-26", "https://x", "v1.1.0-rc.2")
    except SystemExit as e:
        assert "nothing listed" in str(e)
    else:
        raise AssertionError("expected failure")

    # First release ever.
    first = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- x\n"
    out, _ = release(first, "0.1.0", "2026-01-01", "https://x", "")
    assert out.endswith(
        "[Unreleased]: https://x/compare/v0.1.0...HEAD\n[0.1.0]: https://x/releases/tag/v0.1.0\n"
    ), out
    print("ok")


def main(argv):
    if argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(argv) not in (5, 6):
        raise SystemExit(__doc__)
    version, date, url, prev_tag = argv[1:5]
    path = argv[5] if len(argv) == 6 else "CHANGELOG.md"
    with open(path, encoding="utf-8") as f:
        text = f.read()
    out, folded = release(text, version, date, url, prev_tag)
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
    if folded:
        print(f"folded {', '.join(folded)} into {version}")


if __name__ == "__main__":
    main(sys.argv)
