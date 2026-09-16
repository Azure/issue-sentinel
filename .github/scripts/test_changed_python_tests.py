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
    def _selectors(self, before, after, siblings=None):
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
            for name, source in (siblings or {}).items():
                path.with_name(name).write_text(source, encoding="utf-8")
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

    def test_file_and_class_name_collision_uses_methods(self):
        before = ""
        after = """\
class test_sample:
    def test_one(self):
        assert True

    def test_two(self):
        assert True
"""
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_one", "sample.test_two"],
        )

    def test_file_collision_with_duplicate_methods_uses_classes(self):
        source = """\
class FirstTests:
    def test_create(self):
        assert True

class SecondTests:
    def test_create(self):
        assert True
"""
        sibling = """\
class test_sample:
    def test_other(self):
        assert True
"""
        self.assertEqual(
            self._selectors("", source, {"test_other.py": sibling}),
            ["sample.FirstTests", "sample.SecondTests"],
        )

    def test_private_test_class_falls_back_to_file(self):
        after = """\
class ExistingTests:
    def test_existing(self):
        assert True

class _PrivateTests:
    def test_private(self):
        assert True
"""
        self.assertEqual(
            self._selectors(
                """\
class ExistingTests:
    def test_existing(self):
        assert True
""",
                after,
            ),
            ["sample.test_sample"],
        )

    def test_changed_base_class_falls_back_to_file(self):
        before = """\
class BaseTests:
    def test_base(self):
        assert True

class DerivedTests(BaseTests):
    def test_derived(self):
        assert True
"""
        after = before.replace(
            "    def test_base(self):\n        assert True",
            """\
    def test_base(self):
        assert True

    def test_added(self):
        assert True""",
        )
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_sample"],
        )

    def test_private_descendant_also_forces_file_fallback(self):
        before = """\
class BaseTests:
    def test_base(self):
        assert True

class _PrivateDerivedTests(BaseTests):
    pass
"""
        after = before.replace(
            "    def test_base(self):\n        assert True",
            """\
    def test_base(self):
        assert True

    def test_added(self):
        assert True""",
        )
        self.assertEqual(
            self._selectors(before, after),
            ["sample.test_sample"],
        )

    def test_inherited_only_class_with_file_collision_fails_closed(self):
        source = """\
class BaseTests:
    def test_inherited(self):
        assert True

class DerivedTests(BaseTests):
    pass
"""
        sibling = """\
class test_sample:
    def test_other(self):
        assert True
"""
        with self.assertRaisesRegex(
            ValueError,
            "azdev cannot uniquely select changed test file",
        ):
            self._selectors("", source, {"test_other.py": sibling})

    def test_top_level_test_with_file_collision_fails_closed(self):
        source = """\
def test_top_level():
    assert True

class PublicTests:
    def test_public(self):
        assert True
"""
        sibling = """\
class test_sample:
    def test_other(self):
        assert True
"""
        with self.assertRaisesRegex(
            ValueError,
            "azdev cannot uniquely select changed test file",
        ):
            self._selectors("", source, {"test_other.py": sibling})

    def test_azdev_resolution_exposes_wrong_suffix_match(self):
        index = {
            "DnsZoneExportTest": "/checkout/other/tests/latest/test_dns.py",
            "network.DnsZoneExportTest": (
                "/checkout/network/tests/latest/test_dns_commands.py"
            ),
        }
        self.assertEqual(
            MODULE._resolve_azdev_selector(index, "network.DnsZoneExportTest"),
            "/checkout/other/tests/latest/test_dns.py",
        )

    def test_package_qualifiers_match_azdev(self):
        self.assertEqual(
            MODULE._module_name(
                "src/ssh/azext_ssh/tests/latest/test_custom.py",
            ),
            "azext_ssh",
        )
        self.assertEqual(
            MODULE._module_name(
                "src/ssh/azext_ssh/tests/latest/test_.py",
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
