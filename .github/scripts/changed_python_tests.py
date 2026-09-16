#!/usr/bin/env python3
"""Select changed Python tests without running unrelated tests in the same file."""

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path


HUNK = re.compile(
    r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@",
)
COMMAND_TEST = re.compile(
    r"^src/azure-cli/azure/cli/command_modules/([^/]+)/tests/latest/test_[^/]*\.py$",
)
EXTENSION_TEST = re.compile(
    r"^src/[^/]+/(azext_[^/]+)/tests/latest/test_[^/]*\.py$",
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
            if not isinstance(node, ast.ClassDef) or node.name.startswith("_"):
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


def _has_descendant(tree, class_name):
    descendants = {class_name}
    while True:
        found = {
            node.name
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            if any(
                isinstance(base, ast.Name) and base.id in descendants
                for base in node.bases
            )
        }
        if found <= descendants:
            return len(descendants) > 1
        descendants.update(found)


def _has_complex_pytest_collection(tree):
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
        for node in tree.body
    ):
        return True
    classes = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    for name, node in classes.items():
        has_tests = any(
            isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
            for child in node.body
        )
        if name.startswith("_") and has_tests:
            return True
        if node.bases and not has_tests:
            return True
        if any(
            isinstance(base, ast.Name) and base.id in classes
            for base in node.bases
        ):
            return True
    return False


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
    if _has_complex_pytest_collection(tree):
        raise ValueError(f"azdev cannot uniquely select changed test file: {path}")
    test_classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_")
        if any(
            isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
            for child in node.body
        )
    ]
    if test_classes and all(
        _azdev_key_count(path, node.name) == 1 for node in test_classes
    ):
        return [f"{module}.{node.name}" for node in test_classes]

    methods = [
        child.name
        for node in test_classes
        for child in node.body
        if (
            isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name.startswith("test_")
        )
    ]
    if methods and all(_azdev_key_count(path, name) == 1 for name in methods):
        return [f"{module}.{name}" for name in methods]
    raise ValueError(f"azdev cannot uniquely select changed test file: {path}")


def _resolve_azdev_selector(index, selector):
    parts = selector.split(".")
    # Match azdev's _find_test exactly: it tries the bare suffix first and
    # expands toward the fully qualified selector.
    for length in range(1, len(parts) + 1):
        candidate = ".".join(parts[-length:])
        if candidate in index:
            return index[candidate]
    raise KeyError(selector)


def _validate_azdev_manifest(manifest_path):
    from azdev.operations.testtool import _get_test_index
    from azdev.operations.testtool.profile_context import current_profile

    entries = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    selectors = {entry["selector"] for entry in entries}
    index = _get_test_index(
        current_profile(),
        True,
        target_tests=selectors,
    )
    errors = []
    for entry in entries:
        selector = entry["selector"]
        expected = Path(entry["path"]).resolve()
        try:
            resolved = _resolve_azdev_selector(index, selector)
        except KeyError:
            errors.append(f"{selector}: not found in the fresh azdev index")
            continue
        actual = Path(resolved.split("::", 1)[0]).resolve()
        if actual != expected:
            errors.append(
                f"{selector}: resolved to {actual}, expected changed file {expected}",
            )
    if errors:
        raise ValueError("Unsafe azdev selector resolution:\n" + "\n".join(errors))


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
        if not isinstance(node, ast.ClassDef) or node.name.startswith("_"):
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
        if _has_descendant(tree, node.name):
            return _fallback_selectors(path, module)
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
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--base")
    mode.add_argument("--validate-manifest")
    parser.add_argument("--manifest")
    args = parser.parse_args()
    if args.validate_manifest:
        _validate_azdev_manifest(args.validate_manifest)
        return

    paths = [line.strip() for line in sys.stdin if line.strip()]
    selectors = []
    manifest = []
    for path in paths:
        file_selectors = _selectors_for_file(args.base, path)
        selectors.extend(file_selectors)
        manifest.extend(
            {"selector": selector, "path": str(Path(path).resolve())}
            for selector in file_selectors
        )
    if args.manifest:
        Path(args.manifest).write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
    print(" ".join(dict.fromkeys(selectors)))


if __name__ == "__main__":
    main()
