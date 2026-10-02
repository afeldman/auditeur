#!/usr/bin/env python3
"""Compose the GitHub release body for a tag.

Used by `.github/workflows/release.yml`. Nothing in the body is written by hand
in the workflow: the highlights come from the matching section of `CHANGELOG.md`
and the artifact table is derived from the archives that were actually built, so
the notes cannot drift away from the release they describe.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from release_artifacts import UNIX_SUFFIX, WINDOWS_SUFFIX, archive_name  # noqa: E402

DESCRIPTION = "Local Evidence-Driven Software Auditor."


class NotesError(Exception):
    """A failure that should be reported without a traceback."""


def changelog_section(changelog: pathlib.Path, version: str) -> str:
    """The body of the `## [<version>]` section, without its heading."""
    if not changelog.is_file():
        raise NotesError(f"{changelog} does not exist; the release notes are derived from it")

    lines = changelog.read_text(encoding="utf-8").splitlines()
    heading = re.compile(rf"^##\s+\[?{re.escape(version)}\]?(?:\s|$)")
    start = None
    for index, line in enumerate(lines):
        if heading.match(line):
            start = index + 1
            break
    if start is None:
        raise NotesError(f"{changelog} has no '## {version}' section; add one before tagging")

    body: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        body.append(line)

    # Drop the link definitions a Keep a Changelog file keeps at the bottom.
    while body and (not body[-1].strip() or re.match(r"^\[[^\]]+\]:\s", body[-1])):
        body.pop()
    while body and not body[0].strip():
        body.pop(0)

    if not body:
        raise NotesError(f"the '## {version}' section of {changelog} is empty")
    return "\n".join(body)


def built_targets(dist_dir: pathlib.Path, tag: str) -> list[str]:
    prefix = f"auditeur-{tag}-"
    targets = []
    for entry in sorted(dist_dir.iterdir()):
        for suffix in (UNIX_SUFFIX, WINDOWS_SUFFIX):
            if entry.is_file() and entry.name.startswith(prefix) and entry.name.endswith(suffix):
                targets.append(entry.name[len(prefix): -len(suffix)])
    if not targets:
        raise NotesError(f"no release archives for {tag} under {dist_dir}")
    return targets


def compose(tag: str, version: str, highlights: str, targets: list[str], repository: str) -> str:
    base = f"https://github.com/{repository}/releases/download/{tag}"
    table = "\n".join(
        f"| `{target}` | [`{archive_name(tag, target)}`]({base}/{archive_name(tag, target)}) |"
        for target in targets
    )

    return f"""# Auditeur {tag}

{DESCRIPTION}

## Highlights

{highlights}

## Installation

Download the archive for your platform, verify it against `SHA256SUMS`, and put
the binary on your `PATH`:

```sh
TARGET=x86_64-unknown-linux-gnu
BASE={base}

curl -fLO "$BASE/auditeur-{tag}-$TARGET.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing      # macOS: shasum -a 256 -c SHA256SUMS
tar -xzf "auditeur-{tag}-$TARGET.tar.gz"
sudo install "auditeur-{tag}-$TARGET/auditeur" /usr/local/bin/auditeur
```

Every archive contains `auditeur` (or `auditeur.exe` on Windows), `README.md`,
`LICENSE` and `NOTICE`. These are prebuilt binaries: Rust is needed to build
Auditeur from source, not to run it. A local OpenAI-compatible inference server
is optional — an audit completes deterministically without one.

## Artifacts

| Target | Archive |
| --- | --- |
{table}

## Checksums

See `SHA256SUMS`.

## Documentation

See `README.md`.

## Source

This release corresponds exactly to Git tag `{tag}`.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", required=True, help="release tag, e.g. v0.1.0")
    parser.add_argument("--version", required=True, help="package version the tag must match, e.g. 0.1.0")
    parser.add_argument("--changelog", default="CHANGELOG.md")
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument("--repository", default="", help="owner/name, used to build artifact URLs")
    parser.add_argument("--out", default="release-notes.md")
    args = parser.parse_args(argv)

    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repository):
        print(f"error: --repository must be 'owner/name', got {args.repository!r}", file=sys.stderr)
        return 1

    try:
        highlights = changelog_section(pathlib.Path(args.changelog), args.version)
        targets = built_targets(pathlib.Path(args.dist_dir), args.tag)
    except NotesError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1

    body = compose(args.tag, args.version, highlights, targets, args.repository)
    pathlib.Path(args.out).write_text(body, encoding="utf-8")
    print(f"wrote {args.out} ({len(body)} bytes, {len(targets)} artifacts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
