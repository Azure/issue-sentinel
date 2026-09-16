import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("changed_python_tests.py")
SPEC = importlib.util.spec_from_file_location("changed_python_tests", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ChangedPythonTestsTest(unittest.TestCase):
    def _selectors(self, before, after):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.com"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=root,
                check=True,
            )
            path = (
                root / "src" / "azure-cli" / "azure" / "cli"
                / "command_modules" / "sample" / "tests" / "latest"
                / "test_sample.py"
            )
            path.parent.mkdir(parents=True)
            path.write_text(before, encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "base"],
                cwd=root,
                check=True,
            )
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            path.write_text(after, encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "change"],
                cwd=root,
                check=True,
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                return MODULE._selectors_for_file(
                    base,
                    str(path.relative_to(root)),
                )
            finally:
                os.chdir(previous)

    def test_new_class_ignores_supporting_imports(self):
        before = """\
class ExistingTests:
    def test_existing(self):
        assert True
"""
        after = """\
from unittest.mock import Mock

class ExistingTests:
    def test_existing(self):
        assert True

class AddedTests:
    def test_added(self):
        assert Mock()
"""
        self.assertEqual(
            self._selectors(before, after),
            ["sample.AddedTests"],
        )

    def test_changed_test_method_falls_back_to_file(self):
        before = """\
class SampleTests:
    def test_one(self):
        assert True

    def test_two(self):
        assert True
"""
        after = before.replace(
            "    def test_two(self):\n        assert True",
            "    def test_two(self):\n        assert 2 + 2 == 4",
        )
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_sample"],
        )

    def test_changed_class_helper_falls_back_to_file(self):
        before = """\
class SampleTests:
    def setUp(self):
        self.value = 1

    def test_value(self):
        assert self.value
"""
        after = before.replace("self.value = 1", "self.value = 2")
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_sample"],
        )

    def test_changed_module_helper_falls_back_to_file(self):
        before = """\
def helper():
    return 1

class SampleTests:
    def test_value(self):
        assert helper()
"""
        after = before.replace("return 1", "return 2")
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_sample"],
        )

    def test_deletion_only_hunk_falls_back_to_file(self):
        before = """\
class SampleTests:
    def test_one(self):
        assert True

    def test_two(self):
        assert True
"""
        after = before.replace(
            "    def test_one(self):\n        assert True\n\n",
            "",
        ).replace(
            "    def test_two(self):\n        assert True",
            "    def test_two(self):\n        assert 2 + 2 == 4",
        )
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_sample"],
        )

    def test_import_replacement_falls_back_to_file(self):
        before = """\
from unittest.mock import Mock

class SampleTests:
    def test_value(self):
        assert Mock()
"""
        after = before.replace(
            "from unittest.mock import Mock",
            "from unittest.mock import MagicMock",
        ).replace("Mock()", "MagicMock()")
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_sample"],
        )

    def test_package_qualifiers_match_azdev(self):
        self.assertEqual(
            MODULE._module_name(
                "src/ssh/azext_ssh/tests/latest/test_custom.py",
            ),
            "azext_ssh",
        )
        self.assertIsNone(
            MODULE._module_name(
                "src/azure-cli-core/azure/cli/core/tests/test_util.py",
            ),
        )
        self.assertIsNone(
            MODULE._module_name(
                "src/networkcloud/azext_networkcloud/tests/unit/test_baremetalmachine.py",
            ),
        )


if __name__ == "__main__":
    unittest.main()
