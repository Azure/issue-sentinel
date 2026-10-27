import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("vm_size_availability.py")
SPEC = importlib.util.spec_from_file_location("vm_size_availability", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SKU_ERROR = (
    "(SkuNotAvailable) The requested VM size for resource 'Following SKUs have failed for "
    "Capacity Restrictions: Standard_D2s_v3' is currently not available in location 'WestUS3'."
)
LOCATION_BLOCK = [{"type": "Location", "reasonCode": "NotAvailableForSubscription"}]
ZONE_BLOCK = [{"type": "Zone", "reasonCode": "NotAvailableForSubscription"}]


def _results(*texts):
    cases = "".join(
        f'<testcase classname="c" name="t{index}"><failure message="m">{text}</failure></testcase>'
        for index, text in enumerate(texts)
    )
    return f"<testsuite>{cases}</testsuite>"


def _list_skus(*args):
    if args[0] == "--size":
        return [
            {"name": "Standard_D2s_v3", "locations": ["westus3"], "restrictions": LOCATION_BLOCK},
            {"name": "Standard_D2s_v3", "locations": ["eastus2"], "restrictions": LOCATION_BLOCK},
            {"name": "Standard_D2s_v3", "locations": ["southcentralus"], "restrictions": ZONE_BLOCK},
            {"name": "Standard_D2s_v3", "locations": ["CentralUS"], "restrictions": []},
            {"name": "Standard_D2s_v3_Promo", "locations": ["eastus"], "restrictions": []},
        ]
    return [
        {"name": "Standard_D2s_v3", "restrictions": LOCATION_BLOCK},
        {"name": "Standard_B2s", "restrictions": []},
        {"name": "Standard_D2s_v5", "restrictions": ZONE_BLOCK},
        {"name": "Standard_M128s", "restrictions": []},
    ]


class VmSizeAvailabilityTest(unittest.TestCase):
    def _run(self, xml, list_skus=_list_skus):
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary, "results.xml")
            output = Path(temporary, "vm-capacity.json")
            results.write_text(xml)
            self.assertEqual(MODULE.main(str(results), str(output), list_skus), 0)
            return json.loads(output.read_text()) if output.exists() else None

    def test_reports_the_regions_and_sizes_the_subscription_allows(self):
        report = self._run(_results(SKU_ERROR, SKU_ERROR, "AssertionError: 1 != 2"))
        self.assertEqual(report["capacity_failures"], [{
            "size": "Standard_D2s_v3",
            "region": "westus3",
            "size_usable_in_region": False,
            "regions_allowing_size": ["centralus", "southcentralus"],
            "sizes_allowed_in_region": ["Standard_D2s_v5", "Standard_B2s"],
        }])

    def test_writes_nothing_without_a_capacity_failure(self):
        self.assertIsNone(self._run(_results("AssertionError: 1 != 2")))
        self.assertIsNone(self._run("not xml"))

    def test_a_failed_lookup_does_not_fail_the_step(self):
        def broken(*args):
            raise MODULE.subprocess.CalledProcessError(1, "az")

        self.assertIsNone(self._run(_results(SKU_ERROR), broken))


if __name__ == "__main__":
    unittest.main()
