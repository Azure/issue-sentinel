#!/usr/bin/env python3
"""Select changed Python tests without running unrelated tests in the same file."""

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path


HUNK = re.compile(
    r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@",
)
COMMAND_TEST = re.compile(
    r"^src/azure-cli/azure/cli/command_modules/([^/]+)/tests/latest/test_[^/]+\.py$",
)
EXTENSION_TEST = re.compile(
    r"^src/[^/]+/(azext_[^/]+)/tests/latest/test_[^/]+\.py$",
)


def _span(node):
    starts = [node.lineno]
    starts.extend(decorator.lineno for decorator in getattr(node, "decorator_list", ()))
    return range(min(starts), node.end_lineno + 1)


def _changed_lines(base, path):
    diff = subprocess.run(
        [
            "git", "diff", "--unified=0", "--diff-filter=ACMR",
            f"{base}...HEAD", "--", path,
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout
    changed = set()
    has_deletions = any(
        line.startswith("-") and not line.startswith("--- ")
        for line in diff.splitlines()
    )
    for line in diff.splitlines():
        match = HUNK.match(line)
        if not match:
            continue
        start = int(match.group(2))
        count = int(match.group(3) or "1")
        changed.update(range(start, start + count))
    return changed, has_deletions


def _imported_names(node):
    if isinstance(node, ast.Import):
        return {
            alias.asname or alias.name.split(".", 1)[0]
            for alias in node.names
        }
    if isinstance(node, ast.ImportFrom):
        return {
            alias.asname or alias.name
            for alias in node.names
            if alias.name != "*"
        }
    return set()


def _ignorable_module_lines(tree, source_lines, selected_lines):
    ignored = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = _imported_names(node)
            usages = [
                child for child in ast.walk(tree)
                if (
                    isinstance(child, ast.Name)
                    and isinstance(child.ctx, ast.Load)
                    and child.id in names
                )
            ]
            if (
                names
                and any(child.lineno in selected_lines for child in usages)
                and not any(child.lineno not in selected_lines for child in usages)
            ):
                ignored.update(_span(node))
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            ignored.update(_span(node))
    ignored.update(
        number
        for number, line in enumerate(source_lines, 1)
        if not line.strip() or line.lstrip().startswith("#")
    )
    return ignored


def _module_name(path):
    command_match = COMMAND_TEST.fullmatch(path)
    if command_match:
        return command_match.group(1)
    extension_match = EXTENSION_TEST.fullmatch(path)
    if extension_match:
        return extension_match.group(1)
    return None


def _azdev_key_count(path, key):
    profile_root = Path(path).parent
    count = 0
    for candidate in profile_root.glob("test_*.py"):
        try:
            source = candidate.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            return None
        if candidate.stem == key:
            count += 1
        try:
            tree = ast.parse(source, filename=str(candidate))
        except SyntaxError:
            return None
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            test_methods = [
                child for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name.startswith("test_")
            ]
            if not test_methods:
                continue
            if node.name == key:
                count += 1
            count += sum(method.name == key for method in test_methods)
    return count


def _class_is_unique(path, class_name):
    return _azdev_key_count(path, class_name) == 1


def _fallback_selectors(path, module):
    stem = Path(path).stem
    if _azdev_key_count(path, stem) == 1:
        return [f"{module}.{stem}"]

    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8-sig"), filename=path)
    except (OSError, UnicodeError, SyntaxError) as error:
        raise ValueError(
            f"azdev cannot uniquely select changed test file: {path}",
        ) from error
    methods = [
        child.name
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        for child in node.body
        if (
            isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
        )
    ]
    if methods and all(_azdev_key_count(path, name) == 1 for name in methods):
        return [f"{module}.{name}" for name in methods]
    raise ValueError(f"azdev cannot uniquely select changed test file: {path}")


def _selectors_for_file(base, path):
    module = _module_name(path)
    if not module:
        raise ValueError(f"Unsupported azdev live-test path: {path}")
    changed, has_deletions = _changed_lines(base, path)
    if has_deletions or not changed:
        return _fallback_selectors(path, module)

    source = Path(path).read_text(encoding="utf-8-sig")
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return _fallback_selectors(path, module)

    selectors = []
    covered = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                lines = set(_span(node))
                covered.update(lines)
                if changed & lines:
                    return _fallback_selectors(path, module)
            continue
        if not isinstance(node, ast.ClassDef):
            continue

        test_methods = [
            child for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
        ]
        if not test_methods:
            continue
        class_lines = set(_span(node))
        changed_in_class = changed & class_lines
        if not changed_in_class:
            covered.update(class_lines)
            continue
        if not module or not _class_is_unique(path, node.name):
            return _fallback_selectors(path, module)
        selectors.append(f"{module}.{node.name}")
        covered.update(class_lines)

    selected_lines = {
        line
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and f"{module}.{node.name}" in selectors
        for line in _span(node)
    }
    ignored = _ignorable_module_lines(
        tree,
        source.splitlines(),
        selected_lines,
    )
    if (changed - covered - ignored) or not selectors:
        return _fallback_selectors(path, module)
    return selectors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    paths = [line.strip() for line in sys.stdin if line.strip()]
    selectors = []
    for path in paths:
        selectors.extend(_selectors_for_file(args.base, path))
    print(" ".join(dict.fromkeys(selectors)))


if __name__ == "__main__":
    main()
