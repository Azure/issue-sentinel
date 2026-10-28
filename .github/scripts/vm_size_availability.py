"""Record which VM sizes and regions the test subscription can use for capacity failures.

A live test that fails with SkuNotAvailable or QuotaExceeded usually picked a size the
subscription is not allowed, or has no core quota for, in that region. Guessing other
regions can loop forever, so this asks Azure which regions allow the failed size with free
quota and which small sizes the failed region allows with free quota, and writes the answer
next to results.xml for the agent to use. A test that crashes in a forked process leaves
only its exit status in results.xml, so the recordings the run regenerated are read too.

Usage: vm_size_availability.py RESULTS_XML OUTPUT_JSON [RECORDING_YAML ...]
"""

import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

_CAPACITY = re.compile(
    r"SkuNotAvailable|AllocationFailed|ZonalAllocationFailed|Overconstrained\w*AllocationRequest"
    r"|is currently not available in location|QuotaExceeded",
)
# A quota error names the family, not the size, so fall back to the size the test passed.
_SIZE = re.compile(r"(?:Capacity Restrictions: |VM size |--size )'?(Standard_[A-Za-z0-9_]+)")
_VM_SIZE = re.compile(r'vmSize\\?"\s*:\s*\\?"(Standard_[A-Za-z0-9_]+)')
_REGION = re.compile(r"(?:in location '?|Location: )([A-Za-z0-9]+)")
# Regions listed for the subscription where live tests can't run.
_UNUSABLE_REGION = re.compile(r"(?:stg|euap)$")
_MAX_QUOTA_LOOKUPS = 8
# Small general-purpose sizes the agent can switch to without changing what a test checks.
PREFERRED_SIZES = (
    "Standard_D2s_v5", "Standard_D2as_v5", "Standard_D2s_v4", "Standard_D2s_v3",
    "Standard_B2s", "Standard_B2ms", "Standard_DS2_v2", "Standard_D2ds_v5", "Standard_E2s_v5",
    "Standard_D2as_v4", "Standard_F2s_v2", "Standard_D2s_v6", "Standard_D2as_v6", "Standard_A2_v2",
)
PREFERRED_REGIONS = (
    "eastus", "eastus2", "westus2", "westus3", "centralus", "southcentralus",
    "northeurope", "westeurope", "uksouth",
)


def _add(pairs, size, region):
    if size and region:
        pair = (size.group(1), region.group(1).lower())
        if pair not in pairs:
            pairs.append(pair)


def capacity_failures(results_xml):
    """Distinct (size, region) pairs from failed test cases that hit a capacity error."""
    pairs = []
    for case in ET.parse(results_xml).getroot().iter("testcase"):
        for child in case:
            if child.tag not in ("failure", "error"):
                continue
            text = f"{child.get('message') or ''}\n{child.text or ''}"
            if _CAPACITY.search(text):
                _add(pairs, _SIZE.search(text), _REGION.search(text))
    return pairs


def recording_failures(paths):
    """(size, region) pairs from recorded requests whose response was a capacity error."""
    pairs = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            continue
        # Each "- request:" starts one interaction.
        for interaction in re.split(r"^- request:", text, flags=re.M)[1:]:
            interaction = _unwrap_yaml(interaction)
            if _CAPACITY.search(interaction):
                # The error names the failed size; a deployment can request several.
                _add(pairs, _SIZE.search(interaction) or _VM_SIZE.search(interaction),
                     _REGION.search(interaction))
    return pairs


def _unwrap_yaml(text):
    """Undo YAML line folding and quote escaping so error text reads as Azure sent it.

    Parsing the cassette would need PyYAML, which the runner's Python may not have.
    """
    text = re.sub(r"\\\n\s*(?:\\(?= ))?", "", text)  # double-quoted line continuation
    text = re.sub(r"\s*\n\s*", " ", text)  # folded line break
    return text.replace("''", "'").replace('\\"', '"').replace("\\\\", "\\")


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


def _usage(region):
    out = subprocess.run(
        ["az", "vm", "list-usage", "--location", region, "--output", "json"],
        check=True, capture_output=True, text=True, timeout=300,
    ).stdout
    return json.loads(out or "[]")


def _vcpus(sku):
    for capability in sku.get("capabilities") or ():
        if capability.get("name") == "vCPUs":
            return int(capability.get("value") or 0)
    return 0


def _free_cores(usage):
    """Free cores by quota name (vCPU family, plus "cores" for the regional total)."""
    return {
        ((item.get("name") or {}).get("value") or "").casefold():
            int(item.get("limit") or 0) - int(item.get("currentValue") or 0)
        for item in usage
    }


def _has_quota(sku, free):
    needed = _vcpus(sku)
    family = (sku.get("family") or "").casefold()
    return (
        free.get(family, 0) >= needed
        and free.get("cores", needed) >= needed
    )


def _ordered(names, preferred):
    rank = {name.casefold(): index for index, name in enumerate(preferred)}
    return sorted(set(names), key=lambda name: (rank.get(name.casefold(), len(rank)), name))


def availability(size, region, list_skus=_skus, list_usage=_usage):
    allowed = {
        location.lower(): sku
        for sku in list_skus("--size", size)
        if (sku.get("name") or "").casefold() == size.casefold() and _usable(sku)
        for location in sku.get("locations") or ()
        if not _UNUSABLE_REGION.search(location.lower())
    }
    # One quota lookup per region, so check the likeliest regions first and stop early.
    regions = []
    for candidate in _ordered(set(allowed) - {region}, PREFERRED_REGIONS)[:_MAX_QUOTA_LOOKUPS]:
        try:
            usage = list_usage(candidate)
        except (subprocess.SubprocessError, OSError, ValueError) as error:
            # Some listed regions aren't enabled for the subscription; skip them.
            print(f"::notice::Skipped {candidate}: {error}")
            continue
        if _has_quota(allowed[candidate], _free_cores(usage)):
            regions.append(candidate)
    free = _free_cores(list_usage(region))
    sizes = [
        sku["name"] for sku in list_skus("--location", region)
        if sku.get("name") in PREFERRED_SIZES and _usable(sku) and _has_quota(sku, free)
    ]
    return {
        "size": size,
        "region": region,
        "size_usable_in_region": region in allowed and _has_quota(allowed[region], free),
        "regions_allowing_size": regions,
        "sizes_allowed_in_region": _ordered(sizes, PREFERRED_SIZES),
    }


def main(results_xml, output_json, recordings=(), list_skus=_skus, list_usage=_usage):
    try:
        pairs = capacity_failures(results_xml)
    except (OSError, ET.ParseError):
        pairs = []
    for pair in recording_failures(recordings):
        if pair not in pairs:
            pairs.append(pair)
    if not pairs:
        return 0
    report = []
    for size, region in pairs:
        try:
            report.append(availability(size, region, list_skus, list_usage))
        except (subprocess.SubprocessError, OSError, ValueError) as error:
            print(f"::warning::Could not look up {size} in {region}: {error}")
    if report:
        with open(output_json, "w", encoding="utf-8") as handle:
            json.dump({"capacity_failures": report}, handle, indent=2)
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3:]))
