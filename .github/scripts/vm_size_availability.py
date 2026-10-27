"""Record which VM sizes and regions the test subscription can use for capacity failures.

A live test that fails with SkuNotAvailable usually picked a size the subscription is not
allowed in that region. Guessing other regions can loop forever, so this asks Azure which
regions allow the failed size and which small sizes the failed region allows, and writes
the answer next to results.xml for the agent to use.

Usage: vm_size_availability.py RESULTS_XML OUTPUT_JSON
"""

import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

_CAPACITY = re.compile(
    r"SkuNotAvailable|AllocationFailed|ZonalAllocationFailed|Overconstrained\w*AllocationRequest"
    r"|is currently not available in location",
)
_SIZE = re.compile(r"(?:Capacity Restrictions: |VM size )(Standard_[A-Za-z0-9_]+)")
_REGION = re.compile(r"in location '?([A-Za-z0-9]+)'?")
# Small general-purpose sizes the agent can switch to without changing what a test checks.
PREFERRED_SIZES = (
    "Standard_D2s_v5", "Standard_D2as_v5", "Standard_D2s_v4", "Standard_D2s_v3",
    "Standard_B2s", "Standard_B2ms", "Standard_DS2_v2", "Standard_D2ds_v5", "Standard_E2s_v5",
)
PREFERRED_REGIONS = (
    "eastus", "eastus2", "westus2", "westus3", "centralus", "southcentralus",
    "northeurope", "westeurope", "uksouth",
)


def capacity_failures(results_xml):
    """Distinct (size, region) pairs from failed test cases that hit a capacity error."""
    pairs = []
    for case in ET.parse(results_xml).getroot().iter("testcase"):
        for child in case:
            if child.tag not in ("failure", "error"):
                continue
            text = f"{child.get('message') or ''}\n{child.text or ''}"
            if not _CAPACITY.search(text):
                continue
            size, region = _SIZE.search(text), _REGION.search(text)
            if size and region:
                pair = (size.group(1), region.group(1).lower())
                if pair not in pairs:
                    pairs.append(pair)
    return pairs


def _usable(sku):
    # Zone restrictions still allow a non-zonal VM; a Location restriction blocks the region.
    return not any(
        (item.get("type") or "").casefold() == "location"
        for item in sku.get("restrictions") or ()
    )


def _skus(*args):
    out = subprocess.run(
        ["az", "vm", "list-skus", "--resource-type", "virtualMachines", "--all",
         "--output", "json", *args],
        check=True, capture_output=True, text=True, timeout=600,
    ).stdout
    return json.loads(out or "[]")


def _ordered(names, preferred):
    rank = {name.casefold(): index for index, name in enumerate(preferred)}
    return sorted(set(names), key=lambda name: (rank.get(name.casefold(), len(rank)), name))


def availability(size, region, list_skus=_skus):
    regions = [
        location.lower()
        for sku in list_skus("--size", size)
        if (sku.get("name") or "").casefold() == size.casefold() and _usable(sku)
        for location in sku.get("locations") or ()
    ]
    sizes = [
        sku["name"] for sku in list_skus("--location", region)
        if sku.get("name") in PREFERRED_SIZES and _usable(sku)
    ]
    return {
        "size": size,
        "region": region,
        "size_usable_in_region": region in regions,
        "regions_allowing_size": _ordered(regions, PREFERRED_REGIONS)[:10],
        "sizes_allowed_in_region": _ordered(sizes, PREFERRED_SIZES),
    }


def main(results_xml, output_json, list_skus=_skus):
    try:
        pairs = capacity_failures(results_xml)
    except (OSError, ET.ParseError):
        return 0
    if not pairs:
        return 0
    report = []
    for size, region in pairs:
        try:
            report.append(availability(size, region, list_skus))
        except (subprocess.SubprocessError, OSError, ValueError) as error:
            print(f"::warning::Could not look up {size} in {region}: {error}")
    if report:
        with open(output_json, "w", encoding="utf-8") as handle:
            json.dump({"capacity_failures": report}, handle, indent=2)
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
