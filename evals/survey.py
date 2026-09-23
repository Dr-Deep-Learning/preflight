#!/usr/bin/env python3
"""Tier 2 survey: scan real AI-built repositories and produce a triage sheet.

Not part of the package and not run by the test suite -- it needs the network and
it is a research tool, not product code.

    uv run python evals/survey.py --targets evals/targets.yaml --out evals/survey

What it does, per target:

1. clones at a **pinned SHA**, so the result is reproducible and citable
2. records which AI-builder fingerprints matched, so "this is a vibe-coded app"
   is evidence rather than assertion
3. runs the scanner and keeps the JSON
4. emits a markdown table with one row per finding and an empty verdict column

Step 4 is the point. Precision is the only measurable thing on real repositories
-- recall is not, because nobody knows the ground truth -- and precision requires
a human to judge every finding. The table is the worksheet for doing that.

Nothing here touches a running application. It clones public source and reads it.
That is categorically different from probing someone's deployment, which the
spec forbids and this tool cannot do.

**If a finding turns out to be a live credential**, that is a real exposure with a
real owner. Disclose privately through the repository's security policy; never
open a public issue containing the key, and never publish the repository name
alongside an unpatched finding.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: Evidence that a repository was built with an AI builder. Presence is a hint,
#: not proof -- record which ones matched and let the reader judge.
FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "lovable": ("package.json:lovable-tagger", "README.md:lovable.dev", "path:.lovable"),
    "bolt": ("path:.bolt", "README.md:bolt.new"),
    "v0": ("README.md:v0.dev", "package.json:v0-sdk"),
    "replit": ("path:.replit", "path:replit.nix"),
    "cursor": ("path:.cursorrules", "path:.cursor"),
    "claude-code": ("path:CLAUDE.md", "path:.claude"),
}


@dataclass
class Target:
    url: str
    sha: str
    note: str = ""

    @property
    def name(self) -> str:
        return (
            self.url.rstrip("/").removesuffix(".git").rsplit("/", 2)[-2:][0]
            + "-"
            + (self.url.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1])
        )


@dataclass
class Surveyed:
    target: Target
    fingerprints: list[str] = field(default_factory=list)
    #: Declared version of each builder's marker dependency, e.g. lovable-tagger.
    #: A *range* ("^1.1.7"), not a resolved version -- the lockfile has that, and
    #: half these repos do not commit one. Enough to separate eras, not enough to
    #: pin a build.
    builder_versions: dict[str, str] = field(default_factory=dict)
    committed_at: str = ""
    result: dict[str, Any] | None = None
    error: str | None = None

    @property
    def coverage(self) -> tuple[int, int]:
        """(rules that ran, rules in the ruleset) for this target's stack.

        The number that explains a clean report. Two of four rules running
        because the stack has no Supabase backend is not evidence the app is
        safe; it is evidence the ruleset had nothing to say about it.
        """
        if self.result is None:
            return (0, 0)
        checks = self.result["checks"]
        return (sum(1 for c in checks if c["status"] != "skipped"), len(checks))


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)


def clone_at(url: str, sha: str, destination: Path) -> None:
    """Blobless clone, then check out the pinned commit. Fast, and reproducible."""
    cloned = run(["git", "clone", "--filter=blob:none", "--quiet", url, str(destination)])
    if cloned.returncode != 0:
        raise RuntimeError(f"clone failed: {cloned.stderr.strip()}")
    checked_out = run(["git", "checkout", "--quiet", sha], cwd=destination)
    if checked_out.returncode != 0:
        raise RuntimeError(f"checkout of {sha} failed: {checked_out.stderr.strip()}")


def detect_fingerprints(root: Path) -> list[str]:
    """Which builders left traces. `path:` checks existence, `file:needle` content."""
    found: list[str] = []
    for builder, markers in FINGERPRINTS.items():
        for marker in markers:
            kind, _, rest = marker.partition(":")
            if kind == "path":
                hit = (root / rest).exists()
            else:
                candidate = root / kind
                hit = (
                    candidate.is_file()
                    and rest.lower()
                    in candidate.read_text(encoding="utf-8", errors="replace").lower()
                )
            if hit:
                found.append(f"{builder} ({marker})")
                break
    return found


#: Marker dependency per builder, read out of package.json as a version proxy.
BUILDER_MARKER_DEPS = {"lovable": "lovable-tagger", "v0": "v0-sdk"}


def builder_versions(root: Path) -> dict[str, str]:
    """Declared version of each builder's marker dependency, if package.json has one."""
    manifest = root / "package.json"
    if not manifest.is_file():
        return {}
    try:
        pkg = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    return {builder: str(deps[dep]) for builder, dep in BUILDER_MARKER_DEPS.items() if dep in deps}


def committed_at(root: Path, sha: str) -> str:
    """Author date of the pinned commit, ISO-8601. The other era proxy, and the
    honest one: a version range tells you what was declared, not when."""
    shown = run(["git", "show", "-s", "--format=%as", sha], cwd=root)
    return shown.stdout.strip() if shown.returncode == 0 else ""


def scan(root: Path) -> dict[str, Any]:
    """Run the installed scanner and return its JSON report."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        report = Path(handle.name)
    completed = run(
        [
            sys.executable,
            "-m",
            "preflight",
            "scan",
            str(root),
            "--json",
            str(report),
            "--fail-on",
            "none",
        ]
    )
    if not report.exists():
        raise RuntimeError(f"scan produced no report: {completed.stderr.strip()[:400]}")
    data: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
    report.unlink(missing_ok=True)
    return data


def survey(targets: list[Target], out: Path) -> list[Surveyed]:
    out.mkdir(parents=True, exist_ok=True)
    results: list[Surveyed] = []

    for target in targets:
        print(f"-> {target.url} @ {target.sha[:8]}", flush=True)
        record = Surveyed(target=target)
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace) / "repo"
            try:
                clone_at(target.url, target.sha, root)
                record.fingerprints = detect_fingerprints(root)
                record.builder_versions = builder_versions(root)
                record.committed_at = committed_at(root, target.sha)
                record.result = scan(root)
            except (RuntimeError, OSError, json.JSONDecodeError) as exc:
                record.error = str(exc)
                print(f"   ! {exc}", flush=True)
        if record.result is not None:
            (out / f"{target.name}.json").write_text(
                json.dumps(record.result, indent=2), encoding="utf-8"
            )
            findings = len(record.result["findings"])
            ran, total = record.coverage
            print(
                f"   {findings} findings, {ran}/{total} rules applicable, "
                f"fingerprints: {record.fingerprints or 'none'}"
            )
        results.append(record)

    return results


def catalog_ids_by_rule() -> dict[str, str]:
    """Rule id -> the catalog entries it implements, so the sheet speaks one
    vocabulary. Imported lazily: the survey runs against an installed scanner."""
    import preflight.rules  # noqa: F401 - populates the registry
    from preflight.engine import REGISTRY

    return {rule.id: ", ".join(rule.catalog_ids) for rule in REGISTRY}


def triage_sheet(results: list[Surveyed]) -> str:
    """One row per finding, with an empty verdict column for a human to fill."""
    catalog = catalog_ids_by_rule()
    lines = [
        "# Tier 2 survey — triage sheet",
        "",
        "Fill in **Verdict** for every row: `TP` (true positive), `FP` (false",
        "positive) or `?` (cannot tell without running the app). Precision is",
        "TP / (TP + FP); recall is not measurable here and must not be reported.",
        "",
        "Every `FP` is a hard negative for the Tier 1 eval set. Every `TP` on an",
        "uncovered pattern is a fixture worth adding.",
        "",
        "> A finding that turns out to be a **live** credential is a real exposure.",
        "> Disclose privately. Do not publish the repository name with it.",
        "",
        "| Repo | SHA | Date | Builder | Version | Rules ran | Rule | Catalog "
        "| Finding | Confidence | Where | Verdict | Note |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]

    for record in results:
        repo = record.target.url.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
        sha = record.target.sha[:8]
        builders = ", ".join(b.split(" ")[0] for b in record.fingerprints) or "**none**"
        versions = ", ".join(f"{k} {v}" for k, v in record.builder_versions.items()) or "—"
        # Leading columns repeat on every row of a repo so the sheet can be
        # pasted into a spreadsheet and grouped without further editing.
        head = f"| {repo} | {sha} | {record.committed_at or '—'} | {builders} | {versions} |"

        if record.error is not None:
            lines.append(f"{head} — | — | — | _{record.error}_ | | | | |")
            continue
        assert record.result is not None
        ran, total = record.coverage
        head += f" {ran}/{total} |"
        if not record.result["findings"]:
            lines.append(f"{head} — | — | _clean_ | | | | |")
            continue
        for finding in record.result["findings"]:
            first = finding["evidence"][0] if finding["evidence"] else {}
            # A file-level finding has no line. `path:None` is not a location.
            line = first.get("line")
            where = f"{first.get('path', '')}:{line}" if line else first.get("path", "")
            lines.append(
                f"{head} {finding['rule_id']} | {catalog.get(finding['rule_id'], '')} | "
                f"{finding['title']} | {finding['confidence']} | `{where}` | | |"
            )

    scanned = [r for r in results if r.error is None]
    total = sum(len(r.result["findings"]) for r in scanned if r.result is not None)
    applicable = sum(r.coverage[0] for r in scanned)
    possible = sum(r.coverage[1] for r in scanned)
    lines += [
        "",
        f"**{len(scanned)} of {len(results)} repositories scanned, {total} findings to triage.**",
        "",
        f"Fingerprint-confirmed as AI-built: "
        f"{sum(1 for r in scanned if r.fingerprints)} of {len(scanned)}. A repository with no",
        "builder evidence is not part of the population and its findings should be",
        "reported separately, if at all.",
        "",
        f"**Rule coverage: {applicable} of {possible} rule-target pairs were applicable.**",
        "A clean report on a target where half the ruleset was skipped is a",
        "statement about the ruleset's stack coverage, not about the app.",
        "",
        "> **Sampling.** These numbers describe the targets in `targets.yaml` and",
        "> nothing else. Hand-picked targets, and targets chosen by looking until",
        "> something was found, do not support a claim about how common a defect",
        "> is -- only about whether this scanner is right when it speaks. Publish",
        "> precision from this sheet; publish a rate only from a sampling frame",
        "> fixed before the first scan.",
    ]
    return "\n".join(lines) + "\n"


def load_targets(path: Path) -> list[Target]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    targets = [Target(**entry) for entry in raw]
    missing = [t.url for t in targets if not t.sha]
    if missing:
        raise SystemExit(f"every target needs a pinned sha; missing for: {missing}")
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=Path("evals/targets.yaml"))
    parser.add_argument("--out", type=Path, default=Path("evals/survey"))
    args = parser.parse_args()

    if not args.targets.is_file():
        raise SystemExit(f"no target list at {args.targets}")

    results = survey(load_targets(args.targets), args.out)
    sheet = args.out / "triage.md"
    sheet.write_text(triage_sheet(results), encoding="utf-8")
    print(f"\ntriage sheet: {sheet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
