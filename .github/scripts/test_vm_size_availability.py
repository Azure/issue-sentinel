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
QUOTA_ERROR = (
    "self.cmd('vm create -g rg -n vm --location westus2 --image Win2022Datacenter "
    "--size Standard_D2s_v5')\n(QuotaExceeded) Operation could not be completed as it results in "
    "exceeding approved standardDSv5Family Cores quota. Additional details - Deployment Model: "
    "Resource Manager, Location: westus2, Current Limit: 0, Current Usage: 0, Additional Required: 2"
)
# A forked test that crashes leaves only its exit status in results.xml; the error is in the
# regenerated recording, with the request body JSON-escaped and long lines wrapped.
CRASH = "test_vm.py:70: running the test EXITED with status 3"
RECORDING = """interactions:
- request:
    body: null
    method: GET
    uri: https://management.azure.com/subscriptions/0/resourcegroups/rg?api-version=2022-09-01
  response:
    body:
      string: '{"location":"westus2"}'
    status:
      code: 200
- request:
    body: '{"properties": {"template": {"resources": [{"type": "Microsoft.Compute/virtualMachines",
      "properties": {"hardwareProfile": {"vmSize": "Standard_D2s_v5"}}}]}}}'
    method: PUT
    uri: https://management.azure.com/subscriptions/0/resourcegroups/rg/providers/Microsoft.Resources/deployments/mock-deployment?api-version=2024-11-01
  response:
    body:
      string: "{\\"error\\":{\\"code\\":\\"InvalidTemplateDeployment\\",\\"details\\":[{\\"code\\":\\"QuotaExceeded\\",\\"message\\":\\"Operation
        could not be completed as it results in exceeding approved standardDSv5Family
        Cores quota. Additional details - Deployment Model: Resource Manager, Location:
        westus2, Current Limit: 0, Current Usage: 0, Additional Required: 2\\"}]}}"
    status:
      code: 400
version: 1
"""
LOCATION_BLOCK = [{"type": "Location", "reasonCode": "NotAvailableForSubscription"}]
ZONE_BLOCK = [{"type": "Zone", "reasonCode": "NotAvailableForSubscription"}]


def _results(*texts):
    cases = "".join(
        f'<testcase classname="c" name="t{index}"><failure message="m">{text}</failure></testcase>'
        for index, text in enumerate(texts)
    )
    return f"<testsuite>{cases}</testsuite>"


FAMILY = {
    "Standard_D2s_v3": "standardDSv3Family", "Standard_D2s_v3_Promo": "standardDSv3PromoFamily",
    "Standard_B2s": "standardBSFamily", "Standard_D2s_v5": "standardDSv5Family",
    "Standard_M128s": "standardMSFamily",
}


def _sku(name, restrictions=(), locations=()):
    return {
        "name": name, "family": FAMILY[name], "locations": list(locations),
        "restrictions": list(restrictions), "capabilities": [{"name": "vCPUs", "value": "2"}],
    }


def _list_skus(*args):
    if args[0] == "--size":
        size = args[1]
        return [
            _sku(size, LOCATION_BLOCK, ["westus3"]),
            _sku(size, LOCATION_BLOCK, ["eastus2"]),
            _sku(size, ZONE_BLOCK, ["southcentralus"]),
            _sku(size, (), ["CentralUS"]),
            _sku(size, (), ["southcentralusstg"]),
            _sku(size, (), ["westus2"]),
            _sku("Standard_D2s_v3_Promo", (), ["eastus"]),
        ]
    return [
        _sku("Standard_D2s_v3", LOCATION_BLOCK),
        _sku("Standard_B2s"),
        _sku("Standard_D2s_v5", ZONE_BLOCK),
        _sku("Standard_M128s"),
    ]


def _list_usage(region):
    # westus2 has no DSv5 quota; every other family and region has room for a 2-core VM.
    limits = {"cores": 100, "standardDSv3Family": 10, "standardDSv5Family": 10, "standardBSFamily": 10}
    if region == "westus2":
        limits["standardDSv5Family"] = 0
    if region == "southcentralus":
        limits["standardDSv3Family"] = 1
    return [{"name": {"value": name}, "currentValue": 0, "limit": limit} for name, limit in limits.items()]


class VmSizeAvailabilityTest(unittest.TestCase):
    def _run(self, xml, list_skus=_list_skus, list_usage=_list_usage, recording=None):
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary, "results.xml")
            output = Path(temporary, "vm-capacity.json")
            results.write_text(xml)
            recordings = []
            if recording is not None:
                recordings.append(str(Path(temporary, "test_vm.yaml")))
                Path(recordings[0]).write_text(recording)
            self.assertEqual(
                MODULE.main(str(results), str(output), recordings, list_skus, list_usage), 0
            )
            return json.loads(output.read_text()) if output.exists() else None

    def test_reports_the_regions_and_sizes_the_subscription_allows(self):
        report = self._run(_results(SKU_ERROR, SKU_ERROR, "AssertionError: 1 != 2"))
        self.assertEqual(report["capacity_failures"], [{
            "size": "Standard_D2s_v3",
            "region": "westus3",
            "size_usable_in_region": False,
            # southcentralus lacks DSv3 quota and the staging region can't run tests.
            "regions_allowing_size": ["westus2", "centralus"],
            "sizes_allowed_in_region": ["Standard_D2s_v5", "Standard_B2s"],
        }])

    def test_quota_failure_reports_sizes_with_free_quota(self):
        report = self._run(_results(QUOTA_ERROR))
        self.assertEqual(report["capacity_failures"], [{
            "size": "Standard_D2s_v5",
            "region": "westus2",
            "size_usable_in_region": False,
            "regions_allowing_size": ["centralus", "southcentralus"],
            "sizes_allowed_in_region": ["Standard_B2s"],
        }])

    def test_crashed_test_reads_the_failure_from_its_recording(self):
        report = self._run(_results(CRASH), recording=RECORDING)
        self.assertEqual(
            [(item["size"], item["region"]) for item in report["capacity_failures"]],
            [("Standard_D2s_v5", "westus2")],
        )
        self.assertEqual(report["capacity_failures"][0]["sizes_allowed_in_region"], ["Standard_B2s"])

    def _recorded(self, recording):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "test_vm.yaml")
            path.write_text(recording)
            return MODULE.recording_failures([str(path)])

    def test_recording_decodes_single_quoted_yaml(self):
        recording = (
            "interactions:\n- request:\n    body: null\n    method: PUT\n  response:\n"
            "    body:\n      string: '{\"error\":{\"code\":\"SkuNotAvailable\",\"message\":\"The\n"
            "        requested VM size for resource ''Following SKUs have failed for Capacity\n"
            "        Restrictions: Standard_D2s_v3'' is currently not available in location\n"
            "        ''WestUS3''.\"}}'\n"
        )
        self.assertEqual(self._recorded(recording), [("Standard_D2s_v3", "westus3")])

    def test_recording_decodes_double_quoted_line_continuation(self):
        recording = (
            "interactions:\n- request:\n    body: '{\"vmSize\": \"Standard_D2s_v4\"}'\n"
            "  response:\n    body:\n"
            "      string: \"{\\\"error\\\":{\\\"code\\\":\\\"QuotaExceeded\\\",\\\"message\\\":\\\"standardDSv4Family\n"
            "        Cores quota. Location:\\\n        \\ westus2, Current Limit: 0\\\"}}\"\n"
        )
        self.assertEqual(self._recorded(recording), [("Standard_D2s_v4", "westus2")])

    def test_recording_prefers_the_size_named_in_the_error(self):
        recording = (
            "interactions:\n- request:\n    body: '{\"resources\": [{\"vmSize\": \"Standard_B2s\"},\n"
            "      {\"vmSize\": \"Standard_D2s_v3\"}]}'\n  response:\n    body:\n"
            "      string: '{\"error\":{\"code\":\"SkuNotAvailable\",\"message\":\"Capacity Restrictions:\n"
            "        Standard_D2s_v3 is currently not available in location ''eastus''.\"}}'\n"
        )
        self.assertEqual(self._recorded(recording), [("Standard_D2s_v3", "eastus")])

    def test_a_region_whose_quota_lookup_fails_is_skipped(self):
        def usage(region):
            if region == "centralus":
                raise MODULE.subprocess.CalledProcessError(1, "az")
            return _list_usage(region)

        report = self._run(_results(QUOTA_ERROR), list_usage=usage)
        self.assertEqual(report["capacity_failures"][0]["regions_allowing_size"], ["southcentralus"])
        self.assertEqual(report["capacity_failures"][0]["sizes_allowed_in_region"], ["Standard_B2s"])

    def test_writes_nothing_without_a_capacity_failure(self):
        self.assertIsNone(self._run(_results("AssertionError: 1 != 2")))
        self.assertIsNone(self._run("not xml"))
        self.assertIsNone(self._run(_results(CRASH), recording=RECORDING.replace("QuotaExceeded", "Other")))

    def test_a_failed_lookup_does_not_fail_the_step(self):
        def broken(*args):
            raise MODULE.subprocess.CalledProcessError(1, "az")

        self.assertIsNone(self._run(_results(SKU_ERROR), broken))


if __name__ == "__main__":
    unittest.main()
