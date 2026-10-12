#!/usr/bin/env python3
"""Delete leftover live-reproduction resource groups (``live-repro-janitor.yml``).

Every reproduction creates ``xea-repro-*`` tagged with ``expiresAt`` and
deletes it with ``if: always()``. This scheduled backstop deletes groups
with that reserved prefix whose ``expiresAt`` has passed, or whose tag is
missing or unparseable. Command output goes to files under ``repro/raw``;
the log shows only counts and group names.
"""

import datetime as dt
import os
import sys

import repro_policy as policy
import repro_runner as runner

PREFIX = f"{policy.REPRO_RESOURCE_GROUP_PREFIX}-"


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=dt.timezone.utc)


def select_expired(groups, now=None):
    """Names of reproduction groups that are past ``expiresAt``."""
    now = now or dt.datetime.now(dt.timezone.utc)
    expired = []
    for group in groups or []:
        if not isinstance(group, dict):
            continue
        name = group.get("name")
        if not isinstance(name, str) or not name.startswith(PREFIX):
            continue
        tags = group.get("tags") or {}
        expires = parse_time(tags.get(policy.REPRO_EXPIRES_TAG))
        if expires is None or expires <= now:
            expired.append(name)
    return sorted(expired)


def main(env=None):
    env = os.environ if env is None else env
    dry_run = str(env.get("REPRO_JANITOR_DRY_RUN", "")).lower() == "true"
    az = runner.system_az()
    listing = runner.run_quiet([
        az, "group", "list", "--query",
        f"[?starts_with(name, '{PREFIX}')].{{name: name, tags: tags}}",
        "-o", "json", "--only-show-errors",
    ], runner.RAW_DIR / "janitor" / "group-list", timeout=600)
    groups = runner._read_json(listing["stdout"])
    if listing["exit_code"] != 0 or not isinstance(groups, list):
        print("::error::Listing reproduction resource groups failed.")
        return 1
    expired = select_expired(groups)
    print(f"{len(groups)} reproduction group(s); {len(expired)} expired.")
    failures = 0
    for index, name in enumerate(expired):
        if dry_run:
            print(f"would delete {name}")
            continue
        result = runner.run_quiet(
            [az, "group", "delete", "--name", name, "--yes", "--no-wait",
             "--only-show-errors"],
            runner.RAW_DIR / "janitor" / f"group-delete-{index}", timeout=600,
        )
        ok = result["exit_code"] == 0
        failures += 0 if ok else 1
        print(f"{'deleting' if ok else 'failed to delete'} {name}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
