"""The architecture, asserted rather than described.

The central design claim of this project is that the language model explains and
never detects, and that this is enforced by structure rather than by a prompt.
A paragraph in a docstring is not enforcement. These tests are.

They read the import graph out of the source with `ast` and fail the build the
moment a dependency points the wrong way. Someone adding a convenient import six
months from now finds out immediately, which is the only kind of architectural
rule that survives.
"""

from __future__ import annotations

import ast
import pathlib

import preflight

PACKAGE_ROOT = pathlib.Path(preflight.__file__).resolve().parent

ENGINE = "preflight.engine"
EXPLAIN = "preflight.explain"


def modules_imported_by(path: pathlib.Path) -> set[str]:
    """Every module name this file imports, however it spells the import."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            for alias in node.names:
                found.add(f"{node.module}.{alias.name}")
    return found


def python_files(subpackage: str) -> list[pathlib.Path]:
    return sorted((PACKAGE_ROOT / subpackage).rglob("*.py"))


def reaches(imported: set[str], target: str) -> bool:
    return any(name == target or name.startswith(target + ".") for name in imported)


def test_the_import_scan_actually_finds_files():
    """Guard the guard.

    Every test below is a negative assertion over a set of files. If the glob ever
    returned nothing -- a rename, a moved package -- they would all pass while
    checking nothing at all. This is the test that notices.
    """
    assert len(python_files("explain")) >= 3
    assert len(python_files("rules")) >= 5
    assert (PACKAGE_ROOT / "engine.py").is_file()


def test_the_explain_package_never_imports_the_engine():
    """The LLM boundary. If this fails, it stopped being structural.

    `Explainer` lives in `preflight.models` precisely so that this package can be
    typed correctly without needing the engine.
    """
    for path in python_files("explain"):
        imported = modules_imported_by(path)
        assert not reaches(imported, ENGINE), (
            f"{path.relative_to(PACKAGE_ROOT)} imports {ENGINE}. The explanation layer "
            "must not be able to reach detection -- get the type from preflight.models."
        )


def test_the_engine_never_imports_the_explain_package():
    """The other direction: detection must not know any concrete explainer exists."""
    imported = modules_imported_by(PACKAGE_ROOT / "engine.py")
    assert not reaches(imported, EXPLAIN)


def test_rules_never_import_the_explain_package():
    """A rule that could call an explainer could launder a model's opinion into a
    finding, which is the exact failure the architecture exists to prevent."""
    for path in python_files("rules"):
        imported = modules_imported_by(path)
        assert not reaches(imported, EXPLAIN), (
            f"{path.relative_to(PACKAGE_ROOT)} imports {EXPLAIN}. Rules are deterministic."
        )


def test_models_depends_on_nothing_inside_preflight():
    """`models` is the bottom of the stack. Everything may import it; it imports
    nothing of ours, which is what lets both `engine` and `explain` share the
    `Explainer` protocol without either importing the other."""
    imported = modules_imported_by(PACKAGE_ROOT / "models.py")
    assert not any(name.startswith("preflight") for name in imported)
