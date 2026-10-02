#!/usr/bin/env python3
"""Package and verify Auditeur release archives.

Used by `.github/workflows/release.yml`. Standard library only, so the same code
runs on a GitHub runner and on a developer machine — which is what makes the
packaging step verifiable before a tag exists.

Archive layout: one top-level directory per archive, named after the archive
itself, so extracting in a shared directory cannot scatter files:

    auditeur-v0.1.0-aarch64-apple-darwin/
        auditeur
        README.md
        LICENSE
        NOTICE

Unix targets become `.tar.gz`, Windows targets `.zip`. Every entry is written
with fixed metadata (mode, uid/gid, mtime from `SOURCE_DATE_EPOCH`), so
packaging the same inputs twice produces byte-identical archives.

The archive contents are copied from an explicit allowlist of files. Nothing is
globbed out of the workspace, so Auditeur's local state (`~/auditeur`, its runs,
logs, model files or caches) cannot end up in a release even by accident.

Subcommands:

    package   bins/ + repository documents -> dist/ + dist/SHA256SUMS
    verify    re-read dist/ and check it against the tag and the documents
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import pathlib
import stat
import sys
import tarfile
import time
import zipfile

#: Files every archive carries in addition to the binary.
DOCUMENTS = ("README.md", "LICENSE", "NOTICE")

#: The binary name on Unix targets.
BINARY = "auditeur"

#: The binary name on Windows targets.
BINARY_WINDOWS = "auditeur.exe"

#: Prefix `actions/download-artifact` adds to the artifact directory name.
ARTIFACT_PREFIX = "bin-"

#: Suffix for Unix targets.
UNIX_SUFFIX = ".tar.gz"

#: Suffix for Windows targets.
WINDOWS_SUFFIX = ".zip"

#: Timestamp used when `SOURCE_DATE_EPOCH` is unset. 1980-01-01T00:00:00Z is the
#: earliest instant the DOS timestamp in a zip entry can represent, so a single
#: default works for both archive formats.
DEFAULT_EPOCH = 315_532_800

#: Name of the checksum file, in `sha256sum -c` format.
CHECKSUMS = "SHA256SUMS"

#: Path components that must never appear in an archive: Auditeur's own local
#: state, and anything else that is not part of a distribution.
FORBIDDEN_PATH_PARTS = (
    "auditeur-state",
    "runs",
    "logs",
    "cache",
    ".auditeur-project",
)


class ReleaseError(Exception):
    """A packaging or verification failure, reported without a traceback."""


def is_windows(target: str) -> bool:
    return "windows" in target


def binary_name(target: str) -> str:
    return BINARY_WINDOWS if is_windows(target) else BINARY


def archive_name(tag: str, target: str) -> str:
    return f"auditeur-{tag}-{target}{WINDOWS_SUFFIX if is_windows(target) else UNIX_SUFFIX}"


def archive_stem(tag: str, target: str) -> str:
    """The single top-level directory inside the archive."""
    return archive_name(tag, target).removesuffix(WINDOWS_SUFFIX).removesuffix(UNIX_SUFFIX)


def source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        return DEFAULT_EPOCH
    try:
        value = int(raw)
    except ValueError as exc:
        raise ReleaseError(f"SOURCE_DATE_EPOCH is not an integer: {raw!r}") from exc
    return max(DEFAULT_EPOCH, value)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def payloads(tag: str, artifact_dir: str, target: str, bins_dir: pathlib.Path, repo_root: pathlib.Path) -> list[tuple[str, bytes, int]]:
    """The archive members, as (name, content, unix mode) triples."""
    directory = archive_stem(tag, target)

    binary = bins_dir / artifact_dir / binary_name(target)
    if not binary.is_file():
        raise ReleaseError(f"no binary for target {target!r} at {binary}")

    members: list[tuple[str, bytes, int]] = [
        (f"{directory}/{binary_name(target)}", binary.read_bytes(), 0o755),
    ]
    for document in DOCUMENTS:
        source = repo_root / document
        if not source.is_file():
            raise ReleaseError(
                f"{document} is missing from {repo_root}. A release archive must "
                "carry it; the release is blocked until the file exists."
            )
        members.append((f"{directory}/{document}", source.read_bytes(), 0o644))
    return members


def write_tar_gz(destination: pathlib.Path, members: list[tuple[str, bytes, int]], epoch: int) -> None:
    buffer = io.BytesIO()
    # gzip with mtime 0 and no stored file name: the only varying metadata in a
    # gzip container is the timestamp and the original name.
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, content, mode in members:
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mtime = epoch
                info.mode = mode
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.type = tarfile.REGTYPE
                archive.addfile(info, io.BytesIO(content))
    destination.write_bytes(buffer.getvalue())


def write_zip(destination: pathlib.Path, members: list[tuple[str, bytes, int]], epoch: int) -> None:
    stamp = time.gmtime(epoch)
    date_time = (stamp.tm_year, stamp.tm_mon, stamp.tm_mday, stamp.tm_hour, stamp.tm_min, stamp.tm_sec)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content, mode in members:
            info = zipfile.ZipInfo(name, date_time=date_time)
            # create_system 3 is Unix, and the high 16 bits of external_attr carry
            # the Unix mode, so an extractor restores the executable bit.
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    destination.write_bytes(buffer.getvalue())


def artifacts_from_bins(bins_dir: pathlib.Path) -> list[tuple[str, str]]:
    """(artifact directory name, target triple) for every downloaded binary."""
    if not bins_dir.is_dir():
        raise ReleaseError(f"no artifact directory at {bins_dir}")
    found = []
    for entry in sorted(bins_dir.iterdir()):
        if not entry.is_dir():
            continue
        name = entry.name
        found.append((name, name[len(ARTIFACT_PREFIX):] if name.startswith(ARTIFACT_PREFIX) else name))
    if not found:
        raise ReleaseError(f"no target directories under {bins_dir}")
    return found


def read_archive(path: pathlib.Path) -> dict[str, bytes]:
    """Every member of an archive as {name: content}, for verification."""
    contents: dict[str, bytes] = {}
    try:
        if path.name.endswith(WINDOWS_SUFFIX):
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    contents[info.filename] = archive.read(info)
        else:
            with tarfile.open(path, mode="r:gz") as archive:
                for info in archive.getmembers():
                    if not info.isfile():
                        raise ReleaseError(f"{path.name}: unexpected non-file member {info.name!r}")
                    handle = archive.extractfile(info)
                    if handle is None:
                        raise ReleaseError(f"{path.name}: unreadable member {info.name!r}")
                    contents[info.name] = handle.read()
    except ReleaseError:
        raise
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as error:
        raise ReleaseError(f"{path.name}: unreadable archive ({error})") from error
    return contents


def check_member_paths(path: pathlib.Path, contents: dict[str, bytes]) -> None:
    for name in contents:
        if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
            raise ReleaseError(f"{path.name}: member escapes the archive: {name!r}")
        parts = pathlib.PurePosixPath(name).parts
        if len(parts) != 2:
            raise ReleaseError(f"{path.name}: member is not inside the archive directory: {name!r}")
        for forbidden in FORBIDDEN_PATH_PARTS:
            if forbidden in parts:
                raise ReleaseError(f"{path.name}: member looks like local Auditeur state: {name!r}")


def command_package(args: argparse.Namespace) -> int:
    bins_dir = pathlib.Path(args.bins_dir)
    out_dir = pathlib.Path(args.out_dir)
    repo_root = pathlib.Path(args.repo_root)
    epoch = source_date_epoch()

    for document in DOCUMENTS:
        if not (repo_root / document).is_file():
            raise ReleaseError(
                f"release precondition not met: {repo_root / document} does not exist. "
                "Refusing to invent one — add LICENSE and NOTICE to the repository."
            )

    # Every payload is read and validated before anything is written, so a broken
    # input cannot leave a half-populated dist/ behind.
    prepared = [
        (archive_name(args.tag, target), target, payloads(args.tag, artifact_dir, target, bins_dir, repo_root))
        for artifact_dir, target in artifacts_from_bins(bins_dir)
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, target, members in prepared:
        destination = out_dir / name
        if is_windows(target):
            write_zip(destination, members, epoch)
        else:
            write_tar_gz(destination, members, epoch)
        written.append((name, destination))
        print(f"packaged {name} ({destination.stat().st_size} bytes)")

    lines = [f"{sha256_file(path)}  {name}" for name, path in sorted(written)]
    (out_dir / CHECKSUMS).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out_dir / CHECKSUMS} with {len(lines)} entries")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    bins_dir = pathlib.Path(args.bins_dir)
    out_dir = pathlib.Path(args.out_dir)
    repo_root = pathlib.Path(args.repo_root)
    artifacts = artifacts_from_bins(bins_dir)
    targets = [target for _artifact_dir, target in artifacts]

    if not out_dir.is_dir():
        message = f"{out_dir} does not exist; nothing was packaged"
        print(f"::error::{message}" if args.github_annotations else f"error: {message}", file=sys.stderr)
        return 1

    problems: list[str] = []
    expected_archives = {archive_name(args.tag, target) for target in targets}

    present = {entry.name for entry in out_dir.iterdir() if entry.is_file()}
    if present != expected_archives | {CHECKSUMS}:
        problems.append(
            f"dist/ holds {sorted(present)}, expected {sorted(expected_archives | {CHECKSUMS})}"
        )

    for artifact_dir, target in artifacts:
        name = archive_name(args.tag, target)
        path = out_dir / name
        if not path.is_file():
            problems.append(f"{name} is missing")
            continue

        try:
            contents = read_archive(path)
            check_member_paths(path, contents)

            expected_members = {
                f"{archive_stem(args.tag, target)}/{binary_name(target)}": (
                    bins_dir / artifact_dir / binary_name(target)
                ).read_bytes(),
                **{
                    f"{archive_stem(args.tag, target)}/{document}": (repo_root / document).read_bytes()
                    for document in DOCUMENTS
                },
            }
        except ReleaseError as error:
            problems.append(str(error))
            continue

        if set(contents) != set(expected_members):
            problems.append(f"{name}: members are {sorted(contents)}, expected {sorted(expected_members)}")
        for member, expected in expected_members.items():
            if member in contents and contents[member] != expected:
                problems.append(f"{name}: {member} does not match the file it was packaged from")

        # The binary in the archive must be executable after extraction.
        try:
            if name.endswith(UNIX_SUFFIX):
                with tarfile.open(path, mode="r:gz") as archive:
                    for info in archive.getmembers():
                        if info.name.endswith(binary_name(target)) and not info.mode & stat.S_IXUSR:
                            problems.append(f"{name}: {info.name} is not executable (mode {info.mode:o})")
            else:
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        mode = info.external_attr >> 16
                        if info.filename.endswith(binary_name(target)) and not mode & stat.S_IXUSR:
                            problems.append(f"{name}: {info.filename} is not executable (mode {mode:o})")
        except (tarfile.TarError, zipfile.BadZipFile, OSError) as error:
            problems.append(f"{name}: could not inspect file modes ({error})")

        print(f"verified {name}: {len(contents)} members")

    checksum_file = out_dir / CHECKSUMS
    if not checksum_file.is_file():
        problems.append(f"{CHECKSUMS} is missing")
    else:
        recorded = {}
        for line in checksum_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            digest, separator, filename = line.partition("  ")
            if not separator or not filename.strip():
                problems.append(f"{CHECKSUMS}: malformed line {line!r}")
                continue
            recorded[filename.strip()] = digest.strip()
        if set(recorded) != expected_archives:
            problems.append(f"{CHECKSUMS} lists {sorted(recorded)}, expected {sorted(expected_archives)}")
        for filename in sorted(expected_archives & set(recorded)):
            checksummed = out_dir / filename
            if not checksummed.is_file():
                problems.append(f"{CHECKSUMS}: {filename} is listed but missing from {out_dir}")
                continue
            actual = sha256_file(checksummed)
            if recorded[filename] != actual:
                problems.append(f"{CHECKSUMS}: {filename} records {recorded[filename]}, actual {actual}")

    if problems:
        for problem in problems:
            print(f"::error::{problem}" if args.github_annotations else f"error: {problem}", file=sys.stderr)
        return 1

    print(f"verification passed: {len(targets)} archives, {CHECKSUMS} consistent")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    # Shared by every subcommand, so `… verify --github-annotations` works, which
    # is the order the workflow writes its arguments in.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--github-annotations", action="store_true", help="emit GitHub Actions ::error:: lines")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name, handler in (("package", command_package), ("verify", command_verify)):
        sub = subparsers.add_parser(name, help=handler.__doc__, parents=[common])
        sub.add_argument("--tag", required=True, help="release tag, e.g. v0.1.0")
        sub.add_argument("--bins-dir", default="bins", help="directory holding one subdirectory per target")
        sub.add_argument("--out-dir", default="dist", help="directory the archives and SHA256SUMS are written to")
        sub.add_argument("--repo-root", default=".", help="repository root holding README.md, LICENSE and NOTICE")
        sub.set_defaults(handler=handler)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except ReleaseError as error:
        print(f"::error::{error}" if args.github_annotations else f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
