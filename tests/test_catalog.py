"""The defect catalog, and its agreement with the engine.

A schema check that only asked "does this YAML have the right keys" would have
passed on all fifteen files the day they were written, while three quarters of
their globs matched nothing and their severity vocabulary disagreed with the
engine's. So most of this file is not schema validation. It is coherence: the
catalog and the code are two descriptions of one product, and these tests fail
when they drift apart.
"""

from __future__ import annotations

import pathlib

import pytest

import preflight
from conftest import CLEAN, VULNERABLE
from preflight.catalog import (
    CatalogError,
    CatalogSeverity,
    Defect,
    DefectStatus,
    Detector,
    StackToken,
    catalog_by_id,
    get_defect,
    load_catalog,
    parse_defect,
)
from preflight.engine import REGISTRY
from preflight.ingest import LocalDirectorySource, expand_braces
from preflight.models import Severity

CATALOG = load_catalog()

MINIMAL = """
id: TST-001
title: A test defect
category: secrets
severity: high
detector: rule
status: active
applies_to:
  stacks: [any]
  globs: ["**/*.ts"]
cwe: [798]
description: d
why_ai_apps: w
bad_example: b
good_example: g
false_positive_notes: f
references: []
"""


# --- shape -------------------------------------------------------------------


def test_the_catalog_loads():
    assert len(CATALOG) >= 15
    assert all(isinstance(defect, Defect) for defect in CATALOG)


def test_ids_are_unique():
    ids = [defect.id for defect in CATALOG]
    assert len(ids) == len(set(ids))


def test_ids_are_sorted_and_well_formed():
    ids = [defect.id for defect in CATALOG]
    assert ids == sorted(ids)
    for defect in CATALOG:
        prefix, _, number = defect.id.partition("-")
        assert prefix.isupper()
        assert number.isdigit() and len(number) == 3


def test_every_entry_carries_the_fields_the_llm_layer_will_need():
    """`false_positive_notes` feeds the prompt and defines the eval hard
    negatives, so an entry without it is not usable by the layer it exists for."""
    for defect in CATALOG:
        assert defect.false_positive_notes.strip()
        assert defect.bad_example.strip()
        assert defect.good_example.strip()


def test_the_catalog_lives_inside_the_package():
    """Not a style point: the Dockerfile copies `src` and nothing else, so a
    catalog outside the package would break the container while every local run
    kept working."""
    package_dir = pathlib.Path(preflight.__file__).resolve().parent
    assert (package_dir / "defects").is_dir()
    assert list((package_dir / "defects").glob("*.yaml"))


# --- rejection ---------------------------------------------------------------


def test_invalid_yaml_is_rejected():
    with pytest.raises(CatalogError, match="not valid YAML"):
        parse_defect("id: [unclosed", source="bad.yaml")


def test_a_missing_field_is_rejected():
    without_notes = "\n".join(
        line for line in MINIMAL.splitlines() if not line.startswith("false_positive_notes")
    )
    with pytest.raises(CatalogError):
        parse_defect(without_notes, source="bad.yaml")


def test_an_unknown_stack_token_is_rejected():
    """A typo in `stacks` must fail loudly rather than gate on nothing."""
    with pytest.raises(CatalogError):
        parse_defect(MINIMAL.replace("[any]", "[nextjs, sveltekit]"), source="bad.yaml")


def test_an_unknown_severity_is_rejected():
    with pytest.raises(CatalogError):
        parse_defect(MINIMAL.replace("severity: high", "severity: P1"), source="bad.yaml")


def test_a_malformed_id_is_rejected():
    with pytest.raises(CatalogError):
        parse_defect(MINIMAL.replace("id: TST-001", "id: tst-1"), source="bad.yaml")


def test_unbalanced_braces_are_rejected():
    with pytest.raises(CatalogError, match="unbalanced braces"):
        parse_defect(MINIMAL.replace('"**/*.ts"', '"**/*.{ts,js"'), source="bad.yaml")


def test_nested_braces_are_rejected():
    with pytest.raises(CatalogError, match="nested braces"):
        parse_defect(MINIMAL.replace('"**/*.ts"', '"**/*.{ts,{js,jsx}}"'), source="bad.yaml")


def test_asking_for_a_defect_that_does_not_exist_is_an_error():
    with pytest.raises(CatalogError, match="no such defect"):
        get_defect("NOPE-999")


# --- brace expansion ---------------------------------------------------------


def test_brace_expansion():
    assert expand_braces("**/*.sql") == ["**/*.sql"]
    assert expand_braces("app/**/*.{js,ts}") == ["app/**/*.js", "app/**/*.ts"]
    assert expand_braces("a.{x,y}.{p,q}") == ["a.x.p", "a.x.q", "a.y.p", "a.y.q"]


def test_expansion_is_what_makes_the_catalog_globs_work():
    """Written as `**/*.{js,jsx,ts,tsx}`, which no Python glob understands."""
    defect = get_defect("SEC-002")
    assert any("{" in glob for glob in defect.applies_to.globs)
    assert not any("{" in pattern for pattern in defect.applies_to.patterns)


# --- agreement with the fingerprint vocabulary -------------------------------


def test_every_catalog_severity_maps_to_a_distinct_engine_severity():
    mapped = {severity: severity.severity for severity in CatalogSeverity}
    assert set(mapped.values()) == set(Severity)


def test_no_entry_constrains_more_than_one_fingerprint_dimension():
    """The tokens in `stacks` are a disjunction -- "Next.js or Express" -- while
    `Applicability` conjoins its dimensions. An entry naming both a framework and
    a backend would therefore mean "or" in the catalog and "and" in the engine,
    and the gate would silently narrow. Nothing does this today; this test is
    what makes it a deliberate decision if something ever wants to."""
    offenders = {
        defect.id: sorted(defect.applies_to.constrained_dimensions)
        for defect in CATALOG
        if len(defect.applies_to.constrained_dimensions) > 1
    }
    assert offenders == {}


def test_a_token_we_cannot_detect_makes_the_gate_permissive():
    """AUTH-005 applies to Next.js, Express or serverless. We can detect the
    first and not the other two, so narrowing to Next.js would skip the check on
    exactly the projects we failed to identify."""
    defect = get_defect("AUTH-005")
    assert StackToken.EXPRESS in defect.applies_to.stacks
    applicability = defect.applies_to.to_applicability()
    assert applicability.frameworks is None
    assert applicability.backends is None


def test_a_fully_detectable_token_set_produces_a_real_gate():
    applicability = get_defect("AUTH-001").applies_to.to_applicability()
    assert applicability.backends is not None
    assert applicability.frameworks is None


def test_react_expands_to_every_react_framework_we_detect():
    """Not one framework: three. Gating "react" on Next.js alone would skip Vite."""
    applicability = get_defect("SEC-002").applies_to.to_applicability()
    assert applicability.frameworks is not None
    assert len(applicability.frameworks) >= 3


# --- agreement with the shipped rules ----------------------------------------


def test_every_rule_declares_catalog_ids_that_exist():
    known = catalog_by_id()
    for rule in REGISTRY:
        assert rule.catalog_ids, f"{rule.id} declares no catalog id"
        for catalog_id in rule.catalog_ids:
            assert catalog_id in known, f"{rule.id} claims {catalog_id}, absent from the catalog"


def test_the_implemented_catalog_entries_are_the_documented_ones():
    implemented = {cid for rule in REGISTRY for cid in rule.catalog_ids}
    assert implemented == {"AUTH-001", "SEC-001", "SEC-002", "SEC-003", "SEC-004", "PAY-001"}


def test_no_two_rules_claim_the_same_catalog_entry():
    claimed = [cid for rule in REGISTRY for cid in rule.catalog_ids]
    assert len(claimed) == len(set(claimed))


#: Catalog entries whose `detector` promises a deterministic rule but which have
#: none yet. Shrinking this list is the roadmap; the test exists so an entry
#: cannot quietly join it.
RULE_PROMISED_BUT_NOT_BUILT = {"AUTH-002", "AUTH-003", "CFG-001", "INJ-001", "INJ-002"}


def test_the_gap_between_promised_and_built_rules_is_the_recorded_one():
    implemented = {cid for rule in REGISTRY for cid in rule.catalog_ids}
    promised = {
        defect.id
        for defect in CATALOG
        if defect.has_rule and defect.status is not DefectStatus.DEPRECATED
    }
    assert promised - implemented == RULE_PROMISED_BUT_NOT_BUILT


#: Where the catalog's severity and the shipped rule's disagree today. Each is a
#: decision, not a bug to paper over: the spec puts webhook verification and
#: browser-reachable third-party keys in Tier 2, while the catalog calls both
#: critical, and the catalog rates a committed .env below a hardcoded key while
#: the rule treats them alike. Resolve them deliberately, then delete the entry.
KNOWN_SEVERITY_DISAGREEMENTS = {
    "SEC-002": (Severity.FATAL, Severity.SERIOUS),
    "SEC-003": (Severity.SERIOUS, Severity.FATAL),
    "PAY-001": (Severity.FATAL, Severity.SERIOUS),
}


def test_catalog_and_rule_severities_agree_except_where_recorded():
    known = catalog_by_id()
    disagreements = {
        catalog_id: (known[catalog_id].engine_severity, rule.severity)
        for rule in REGISTRY
        for catalog_id in rule.catalog_ids
        if known[catalog_id].engine_severity is not rule.severity
    }
    assert disagreements == KNOWN_SEVERITY_DISAGREEMENTS


# --- agreement with the fixture corpus ---------------------------------------

#: Expanded patterns that reach nothing in `fixtures/`. Every one is a gap in the
#: corpus rather than a broken pattern -- no Firebase app, no Express server, no
#: Python or Vue front end, no deployment config. This list is the shopping list
#: for fixtures, and the test below fails when a *new* pattern stops matching,
#: which is how a brace typo or a bad `**` gets caught.
PATTERNS_NOT_EXERCISED_BY_THE_CORPUS = {
    ".env.*.local",
    # The corpus commits one database, `data/app.db`, so `**/*.db` is
    # exercised and its three siblings are not.
    "**/*.db3",
    "**/*.sqlite",
    "**/*.sqlite3",
    ".env.production",
    ".gitignore",
    "**/*.jsx",
    "**/*.py",
    "**/*.toml",
    "**/*.vue",
    "**/*.yaml",
    "**/*.yml",
    "**/*webhook*.ts",
    "api/**/*.ts",
    "app/api/**/*.js",
    "database.rules.json",
    "firestore.rules",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "pages/api/**/*.js",
    "pages/api/**/*.ts",
    "server/**/*.js",
    "server/**/*.py",
    "server/**/*.ts",
    "storage.rules",
    "supabase/functions/**/*.ts",
    "vercel.json",
}


@pytest.fixture(scope="module")
def corpus_indexes():
    return [LocalDirectorySource(root=path).load()[1] for path in (VULNERABLE, CLEAN)]


def test_every_glob_either_reaches_the_corpus_or_is_recorded_as_untested(corpus_indexes):
    unreachable = {
        pattern
        for defect in CATALOG
        for pattern in defect.applies_to.patterns
        if not any(index.matching(pattern) for index in corpus_indexes)
    }
    assert unreachable == PATTERNS_NOT_EXERCISED_BY_THE_CORPUS


def test_a_recursive_glob_actually_recurses(corpus_indexes):
    """The bug this whole change exists for: `PurePath.match` treats a
    mid-pattern `**` as a single `*`, so this matched nothing at all."""
    vulnerable = corpus_indexes[0]
    assert vulnerable.matching("supabase/migrations/**/*.sql")


def test_a_pattern_with_a_slash_is_anchored_to_the_project_root(corpus_indexes):
    """gitignore semantics, and what keeps the existing rule globs behaving."""
    vulnerable = corpus_indexes[0]
    assert vulnerable.matching("supabase/migrations/*.sql")
    assert not vulnerable.matching("migrations/*.sql")


def test_every_defect_reaches_the_corpus_through_at_least_one_pattern(corpus_indexes):
    """Weaker than the list above, and the one that would survive a corpus
    rewrite: no defect may be entirely unreachable."""
    stranded = [
        defect.id
        for defect in CATALOG
        if not any(
            index.matching(pattern)
            for pattern in defect.applies_to.patterns
            for index in corpus_indexes
        )
    ]
    assert stranded == ["AUTH-003"], "AUTH-003 is Firebase; the corpus has no Firebase app"


def test_detectors_are_the_expected_mix():
    counts = {detector: sum(1 for d in CATALOG if d.detector is detector) for detector in Detector}
    assert sum(counts.values()) == len(CATALOG)
    assert counts[Detector.RULE] > 0 and counts[Detector.BOTH] > 0
