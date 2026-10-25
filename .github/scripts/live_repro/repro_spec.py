# GENERATED FILE - DO NOT EDIT.
# Vendored from x-engineering-agent `src/tools/live_tests/reproduction` by
# `scripts/sync_issue_sentinel_repro.py`; edit the source and re-run it.
"""ReproSpec validation, hashing and placeholders copied from the Agent."""

import hashlib
import json
import re

import repro_policy as settings

# Repository kinds, repro tools and Agent forks from the Agent's REPO_PROFILES.
REPO_PROFILES = {
    'Azure/azclips': {'kind': 'dotnet-cli', 'repro_tools': (), 'agent_fork': 'Azure/azclips'},
    'Azure/azure-cli': {'kind': 'cli', 'repro_tools': ('az',), 'agent_fork': 'a0x1ab/azure-cli'},
    'Azure/azure-cli-extensions': {'kind': 'cli-ext', 'repro_tools': ('az',), 'agent_fork': 'a0x1ab/azure-cli-extensions'},
    'Azure/azure-powershell': {'kind': 'powershell', 'repro_tools': ('pwsh-az',), 'agent_fork': 'a0x1ab/azure-powershell'},
    'Azure/terraform-provider-azapi': {'kind': 'terraform-provider', 'repro_tools': (), 'agent_fork': None},
}

REPRO_SPEC_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ReproSpec",
    "type": "object",
    "additionalProperties": False,
    "required": ["issue", "tool", "repro", "observed_in_issue"],
    "properties": {
        "schema_version": {"const": settings.REPRO_SCHEMA_VERSION},
        "issue": {"type": "string", "pattern": r"^Azure/[A-Za-z0-9._-]+#\d+$"},
        "tool": {
            "type": "string",
            "pattern": r"^(az|pwsh-az|az-extension:[a-z][a-z0-9-]{1,63})$",
        },
        "versions": {
            "type": "array", "minItems": 1, "uniqueItems": True,
            "items": {"enum": list(settings.REPRO_VERSIONS)},
        },
        "reported_version": {"type": "string"},
        "os": {"enum": list(settings.REPRO_OPERATING_SYSTEMS)},
        "environment": {"enum": sorted(settings.REPRO_ENVIRONMENTS)},
        "install": {"enum": ["package", "pip"]},
        "azure": {"type": "boolean"},
        "module": {"type": "string", "pattern": r"^Az\.[A-Za-z]{2,40}$"},
        "location": {"type": "string", "minLength": 1},
        "workdir_dirs": {
            "type": "array", "uniqueItems": True,
            "maxItems": settings.REPRO_MAX_WORKDIR_DIRS,
            "items": {
                "type": "string", "pattern": r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$",
            },
        },
        "setup": {"type": "array", "items": {"$ref": "#/$defs/step"}},
        "repro": {
            "type": "array", "minItems": 1,
            "items": {"$ref": "#/$defs/step"},
        },
        "observed_in_issue": {
            "type": "object", "minProperties": 1,
            "additionalProperties": False,
            "properties": {
                "exit_code": {"type": "integer"},
                "error_substring": {"type": "string"},
                "output_substring": {"type": "string"},
            },
        },
        "timeout_minutes": {
            "type": "integer", "minimum": 1,
            "maximum": settings.REPRO_MAX_TIMEOUT_MINUTES,
        },
        "input_file": {
            "type": "object", "additionalProperties": False,
            "required": ["extension", "content"],
            "properties": {
                "extension": {"type": "string", "pattern": r"^[A-Za-z0-9]{1,16}$"},
                "content": {"type": "string", "minLength": 1},
            },
        },
    },
    "$defs": {
        "step": {
            "type": "object",
            "oneOf": [
                {"required": ["argv"]},
                {"required": ["cmdlet", "parameters"]},
                {"required": ["shell", "script"]},
            ],
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"}},
                "shell": {"enum": sorted({
                    shell for shells in settings.REPRO_SHELLS.values()
                    for shell in shells
                })},
                "script": {"type": "string", "minLength": 1},
                "cmdlet": {"type": "string"},
                "parameters": {"type": "object"},
                "expect": {
                    "type": "object", "additionalProperties": False,
                    "properties": {
                        "exit_code": {"type": "integer"},
                        "error_substring": {"type": "string"},
                    },
                },
            },
        },
    },
}

PLACEHOLDERS = (
    "rg", "location", "sub", "password", "file", "name",
    *(f"name{i}" for i in range(1, settings.REPRO_MAX_NAME_PLACEHOLDERS + 1)),
)
_PLACEHOLDER = re.compile(r"\{(rg|location|sub|password|file|name[1-9]?)\}")
_ISSUE = re.compile(r"^(Azure/[A-Za-z0-9._-]+)#([1-9]\d{0,8})$")
_TOOL_EXTENSION = re.compile(r"^az-extension:([a-z][a-z0-9-]{1,63})$")
_VERSION = re.compile(r"^\d{1,4}(?:\.\d{1,4}){1,3}(?:(?:a|b|rc)\d{1,3})?$")
_COMMAND_TOKEN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_LONG_FLAG = re.compile(r"^--[a-z0-9][a-z0-9-]{0,63}$")
_SHORT_FLAG = re.compile(r"^-[A-Za-z]$")
_NUMBER = re.compile(r"^-?\d+(?:\.\d+)?$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]")
_SHELL_META = re.compile(r"""[;&|$`<>()\\"'%]""")
_QUERY_FORBIDDEN = re.compile(r"[;$\\%]")
_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}"
)
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s,;]*")
_BARE_SCHEME = re.compile(
    r"^(?:file|data|javascript|ftp|smb|ssh|git|vbscript):", re.I,
)
_HOST = re.compile(
    r"(?<![\w.{}-])((?:[A-Za-z0-9{}-]+\.)+(?:com|net|org|io|dev|app|xyz|"
    r"info|biz|co|me|ru|cn|sh|ly|ms|cloud|site|online|top|tk|gg|ai|us|uk|"
    r"de|in|tv|cc|link|page|run|so|to|ws|zip|mov))(?![\w-])",
    re.I,
)
_KEY_RUN = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_DOT_SEGMENT = re.compile(r"(?:^|/)\.\.?(?:/|$|\?)")
_RESOURCE_ID = re.compile(
    r"^/subscriptions/\{sub\}(?:/resourcegroups/\{rg\}(?:/[^/?#]+)*)?$", re.I,
)
# Placeholder-style GUIDs such as 00000000-0000-0000-0000-000000000001.
_DUMMY_GUID = re.compile(r"^0{8}-0{4}-0{4}-0{4}-0{8}[0-9a-fA-F]{4}$")
_KEY_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9_.\[\]-]{0,127}=")
_CONFIG_SETTING = re.compile(
    r"^(?:core|output|logging|extension|clients)\.[a-z_]{1,64}"
    r"(?:=[A-Za-z0-9_.-]{0,64})?$"
)
_ARM_URL = re.compile(
    r"^(?:https://management\.azure\.com)?"
    r"/subscriptions/\{sub\}/resourcegroups/\{rg\}(?:/[A-Za-z0-9._{}-]+)*"
    r"(?:\?api-version=\d{4}-\d{2}-\d{2}(?:-preview)?)?$",
    re.I,
)
_API_VERSION_PARAM = re.compile(r"^api-version=\d{4}-\d{2}-\d{2}(?:-preview)?$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_IMAGE_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_LOCAL_PATH = re.compile(r"^(?:/|~|[A-Za-z]:[\\/])|(?:^|[\\/])\.\.(?:[\\/]|$)")
_PS_CMDLET = re.compile(r"^([A-Z][a-z]+)-Az([A-Za-z][A-Za-z0-9]{1,80})$")
_PS_PARAMETER = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_PS_MODULE = re.compile(r"^Az\.[A-Za-z]{2,40}$")
_FILE_EXTENSION = re.compile(r"^[A-Za-z0-9]{1,16}$")
_WORKDIR_DIR = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
_TOP_KEYS = frozenset({
    "schema_version", "issue", "tool", "versions", "reported_version",
    "module",
    "location", "setup", "repro", "observed_in_issue", "timeout_minutes",
    "workdir_dirs", "input_file", "os", "azure", "environment", "install",
})
_INPUT_FILE_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u2028\u2029]")
_OBSERVED_KEYS = frozenset({"exit_code", "error_substring", "output_substring"})
_EXPECT_KEYS = frozenset({"exit_code", "error_substring"})
_REST_FLAGS = frozenset({
    "--method", "-m", "--url", "--uri", "-u", "--uri-parameters",
    "--url-parameters", "--query", "-o", "--output", "--debug", "--verbose",
    "--only-show-errors",
})
_QUERY_FLAGS = frozenset({"--query", "--analytics-query"})
_OUTPUT_FLAGS = frozenset({"-o", "--output"})
_NAME_FLAGS = frozenset({"-n", "--name"})
_MAX_SPEC_JSON_CHARS = 50_000


class ReproSpecError(ValueError):
    """A ReproSpec failed validation; errors lists every problem."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("Invalid ReproSpec: " + "; ".join(self.errors))


def _strip_placeholders(value):
    return _PLACEHOLDER.sub("", value)


def _check_hosts(value, loc, errors):
    """Any host is allowed."""


def _looks_like_key(value):
    for match in _KEY_RUN.finditer(_strip_placeholders(value)):
        run = match.group(0)
        if (any(c.isdigit() for c in run) and any(c.islower() for c in run)
                and any(c.isupper() for c in run)):
            return True
    return False


def _check_sensitive(value, loc, errors):
    """Any value is allowed."""


def _check_resource_ids(value, loc, errors):
    """Any resource ID is allowed."""


def _check_value(value, loc, errors, az=False):
    """Any string is allowed."""
    if not isinstance(value, str):
        errors.append(f"{loc}: must be a string")


def _check_query(value, loc, errors):
    if not isinstance(value, str) or not value:
        errors.append(f"{loc}: must be a non-empty string")


def _check_exact(value, expected, loc, errors, what):
    if value != expected:
        errors.append(f"{loc}: {what} must be {expected}")


def _check_sku(value, loc, errors):
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{loc}: SKU/size must be a non-empty string")


def _check_count(value, loc, errors):
    try:
        count = int(value)
    except (TypeError, ValueError):
        errors.append(f"{loc}: count must be an integer")
        return
    if count < 0:
        errors.append(f"{loc}: count must not be negative")


def _check_name(value, loc, errors):
    _check_value(value, loc, errors)


def _check_text(value, loc, errors):
    """Issue text that the workflow compares as a fixed string."""
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{loc}: must be a non-empty string")


def _special_flag_names():
    return frozenset()


_SCRIPT_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PATH_LIKE = re.compile(r"^\s*(?:[/~\\.@]|[A-Za-z]:)")


def _check_script(value, loc, errors, *, local_path_ok=False):
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{loc}: must be a non-empty string")


def _parse_flags(tokens, loc, errors):
    """Split tokens after the command path into [(flag, [values])]."""
    flags = []
    for token in tokens:
        if token.startswith("-") and not _NUMBER.match(token):
            flag, eq, value = token.partition("=")
            flags.append((flag, [value] if eq else []))
        elif flags:
            flags[-1][1].append(token)
    return flags


_SIGN_IN_GROUPS = frozenset({"login", "logout", "account"})


def _command_allowed(path):
    return True


def _validate_rest(path, flags, loc, errors):
    """Any az rest call is allowed."""


def _check_location(value, loc, errors):
    _check_value(value, loc, errors)


def _check_image(value, loc, errors):
    _check_value(value, loc, errors)


def _validate_flag(flag, values, floc, errors, path=()):
    for value in values:
        _check_value(value, floc, errors, az=True)


def _validate_az_step(step, loc, errors):
    argv = step.get("argv")
    if not isinstance(argv, list) or not all(isinstance(t, str) for t in argv):
        errors.append(f"{loc}.argv: must be a list of strings")
        return None
    if len(argv) < 2 or argv[0] != "az":
        errors.append(f"{loc}.argv: must start with `az` and a command")
        return None
    return {"argv": list(argv)}


def _ps_noun_prefix(noun):
    prefixes = sorted(
        (p for p in settings.REPRO_PS_ALLOWED_NOUN_PREFIXES
         if noun.casefold().startswith(p.casefold())),
        key=len, reverse=True,
    )
    return prefixes[0] if prefixes else None


def ps_cmdlet_module(cmdlet):
    """Az module (Az.<X>) known to ship the cmdlet, else None."""
    match = _PS_CMDLET.match(cmdlet) if isinstance(cmdlet, str) else None
    prefix = _ps_noun_prefix(match.group(2)) if match else None
    return settings.REPRO_PS_NOUN_MODULES.get(prefix) if prefix else None


def _check_ps_cmdlet(cmdlet, loc, errors):
    if not isinstance(cmdlet, str) or not _PS_CMDLET.match(cmdlet):
        errors.append(f"{loc}.cmdlet: must be a `Verb-Az<Noun>` cmdlet name")
        return False
    return True


def _check_ps_value(key, value, loc, errors):
    """Any value is allowed."""


def _validate_ps_step(step, loc, errors):
    cmdlet = step.get("cmdlet")
    parameters = step.get("parameters")
    if not _check_ps_cmdlet(cmdlet, loc, errors):
        return None
    if not isinstance(parameters, dict):
        errors.append(f"{loc}.parameters: must be an object (hashtable)")
        return None
    return {"cmdlet": cmdlet, "parameters": dict(parameters)}


def _validate_expect(value, loc, errors, allowed_keys):
    if not isinstance(value, dict):
        errors.append(f"{loc}: must be an object")
        return None
    unknown = sorted(set(value) - allowed_keys)
    if unknown:
        errors.append(f"{loc}: unknown keys {', '.join(map(str, unknown))}")
    result = {}
    for key in sorted(set(value) & allowed_keys):
        item = value[key]
        if key == "exit_code":
            if isinstance(item, bool) or not isinstance(item, int) or not (
                0 <= item <= 255
            ):
                errors.append(f"{loc}.exit_code: must be an integer 0..255")
                continue
        else:
            _check_text(item, f"{loc}.{key}", errors)
        result[key] = item
    return result


def _validate_shell_step(step, loc, errors, shells):
    shell, script = step.get("shell"), step.get("script")
    if shell not in shells:
        errors.append(f"{loc}.shell: must be one of {list(shells)} on this os")
        return None
    _check_script(script, f"{loc}.script", errors, local_path_ok=True)
    if not isinstance(script, str):
        return None
    return {"shell": shell, "script": script.replace("\r\n", "\n")}


def _validate_steps(steps, name, ps, errors, shells=()):
    if steps is None and name == "setup":
        return []
    if not isinstance(steps, list):
        errors.append(f"{name}: must be a list of steps")
        return []
    normalized = []
    for index, step in enumerate(steps):
        loc = f"{name}[{index}]"
        if not isinstance(step, dict):
            errors.append(f"{loc}: must be an object")
            continue
        shell_step = not ps and ("shell" in step or "script" in step)
        if ps:
            allowed = {"cmdlet", "parameters", "expect"}
        elif shell_step:
            allowed = {"shell", "script", "expect"}
        else:
            allowed = {"argv", "expect"}
        unknown = sorted(set(step) - allowed)
        if unknown:
            errors.append(
                f"{loc}: unknown keys {', '.join(map(str, unknown))} "
                f"(steps for this tool use {', '.join(sorted(allowed))})"
            )
            continue
        if shell_step:
            result = _validate_shell_step(step, loc, errors, shells)
        else:
            result = (_validate_ps_step if ps else _validate_az_step)(
                step, loc, errors,
            )
        if result is None:
            continue
        if "expect" in step:
            result["expect"] = _validate_expect(
                step["expect"], f"{loc}.expect", errors, _EXPECT_KEYS,
            )
        normalized.append(result)
    return normalized


def _parse_spec(spec):
    if isinstance(spec, (str, bytes)):
        if len(spec) > _MAX_SPEC_JSON_CHARS:
            raise ReproSpecError(["spec: too large"])
        try:
            spec = json.loads(spec)
        except ValueError as exc:
            raise ReproSpecError([f"spec: invalid JSON ({exc.msg})"]) from None
    if not isinstance(spec, dict):
        raise ReproSpecError(["spec: must be a JSON object"])
    return spec


def _tool_matches_repository(tool, repository, errors):
    family = "pwsh-az" if tool == "pwsh-az" else "az"
    if family in (REPO_PROFILES.get(repository) or {}).get("repro_tools", ()):
        return
    if family == "pwsh-az":
        errors.append("tool: pwsh-az reproduces Azure PowerShell issues only")
    else:
        errors.append(f"tool: `{tool}` reproduces Azure CLI issues only")


def _validate_input_file(value, errors):
    """Content written to repro-input.<ext>, which {file} points at."""
    loc = "input_file"
    if not isinstance(value, dict) or set(value) != {"extension", "content"}:
        errors.append(f"{loc}: must be an object with extension and content")
        return None
    extension, content = value["extension"], value["content"]
    if not isinstance(extension, str) or not _FILE_EXTENSION.match(extension):
        errors.append(f"{loc}.extension: must be letters and digits")
        return None
    if isinstance(content, str):
        content = content.replace("\r\n", "\n")
    if not isinstance(content, str) or not content:
        errors.append(f"{loc}.content: must be a non-empty string")
        return None
    return {"extension": extension, "content": content}


def input_file_name(spec):
    """File name the runner writes input_file to, or None."""
    input_file = (spec or {}).get("input_file")
    if not input_file:
        return None
    return f"repro-input.{input_file['extension']}"


def _validate_environment(spec, os_name, azure, ps, errors):
    """(environment, install, os) for the named environment; os follows the environment."""
    environment, install = spec.get("environment"), spec.get("install")
    if environment is None:
        if install is not None:
            errors.append("install: only allowed with a container environment")
        return None, None, os_name
    entry = settings.REPRO_ENVIRONMENTS.get(environment) if isinstance(environment, str) else None
    if entry is None:
        errors.append(f"environment: must be one of {sorted(settings.REPRO_ENVIRONMENTS)}")
        return None, None, os_name
    if ps:
        errors.append("environment: only supported for az specs")
    if "os" in spec and spec["os"] != entry["os"]:
        errors.append(f"os: environment `{environment}` runs {entry['os']}")
    if entry["kind"] == "vm" and azure:
        errors.append(
            f"azure: `{environment}` runs steps in a VM that never signs in, so set \"azure\": false"
        )
    if entry["kind"] != "container":
        if install is not None:
            errors.append("install: only allowed with a container environment")
        return environment, None, entry["os"]
    methods = settings.REPRO_CONTAINER_INSTALLS[entry["family"]]
    if install is None:
        install = methods[0]
    elif install not in methods:
        errors.append(f"install: `{environment}` supports {list(methods)}")
    return environment, install, entry["os"]


def _uses_file_placeholder(steps):
    return any(
        "{file}" in json.dumps(step.get("argv") or step.get("parameters"))
        for step in steps
    )


def validate_spec(spec):
    """Validate and normalize a ReproSpec without touching the network.

    Returns valid, errors, spec and spec_hash; defaults are filled so equal intents hash equally.
    """
    try:
        spec = _parse_spec(spec)
    except ReproSpecError as exc:
        return {"valid": False, "errors": exc.errors, "spec": None,
                "spec_hash": None}
    errors = []
    unknown = sorted(set(spec) - _TOP_KEYS)
    if unknown:
        errors.append(f"spec: unknown keys {', '.join(map(str, unknown))}")

    version = spec.get("schema_version", settings.REPRO_SCHEMA_VERSION)
    if version != settings.REPRO_SCHEMA_VERSION:
        errors.append(
            f"schema_version: must be {settings.REPRO_SCHEMA_VERSION}"
        )

    issue = spec.get("issue")
    match = _ISSUE.match(issue) if isinstance(issue, str) else None
    repository = match.group(1) if match else None
    if not match:
        errors.append("issue: must be `Azure/<repo>#<number>`")
    elif repository not in REPO_PROFILES:
        errors.append(f"issue: `{repository}` is not a supported repository")

    tool = spec.get("tool")
    if tool not in ("az", "pwsh-az") and not (
        isinstance(tool, str) and _TOOL_EXTENSION.match(tool)
    ):
        errors.append("tool: must be `az`, `az-extension:<name>` or `pwsh-az`")
        tool = None
    elif repository in REPO_PROFILES:
        _tool_matches_repository(tool, repository, errors)

    versions = spec.get("versions", list(settings.REPRO_DEFAULT_VERSIONS))
    if (not isinstance(versions, list) or not versions
            or any(v not in settings.REPRO_VERSIONS for v in versions)):
        errors.append(
            f"versions: must be a non-empty subset of "
            f"{list(settings.REPRO_VERSIONS)}"
        )
        versions = []
    versions = [v for v in settings.REPRO_VERSIONS if v in versions]

    reported_version = spec.get("reported_version")
    if reported_version is not None and (
        not isinstance(reported_version, str)
        or not _VERSION.match(reported_version)
    ):
        errors.append("reported_version: must look like 2.77.0")
    if "reported" in versions and reported_version is None:
        errors.append('reported_version: required when versions has "reported"')

    location = spec.get("location", settings.REPRO_DEFAULT_LOCATION)
    if not isinstance(location, str) or not location:
        errors.append("location: must be a non-empty string")

    timeout = spec.get(
        "timeout_minutes", settings.REPRO_DEFAULT_TIMEOUT_MINUTES,
    )
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not (
        1 <= timeout <= settings.REPRO_MAX_TIMEOUT_MINUTES
    ):
        errors.append(
            f"timeout_minutes: must be 1..{settings.REPRO_MAX_TIMEOUT_MINUTES}"
        )

    workdir_dirs = spec.get("workdir_dirs", [])
    if (not isinstance(workdir_dirs, list)
            or len(workdir_dirs) > settings.REPRO_MAX_WORKDIR_DIRS
            or len(set(map(str, workdir_dirs))) != len(workdir_dirs)
            or any(not isinstance(d, str) or not _WORKDIR_DIR.match(d)
                   for d in workdir_dirs)):
        errors.append(
            f"workdir_dirs: at most {settings.REPRO_MAX_WORKDIR_DIRS} unique "
            "plain directory names (letters, digits, `_`, `-`)"
        )
        workdir_dirs = []

    input_file = None
    if "input_file" in spec:
        input_file = _validate_input_file(spec["input_file"], errors)

    ps = tool == "pwsh-az"
    os_name = spec.get("os", settings.REPRO_DEFAULT_OS)
    if os_name not in settings.REPRO_OPERATING_SYSTEMS:
        errors.append(
            f"os: must be one of {list(settings.REPRO_OPERATING_SYSTEMS)}"
        )
        os_name = settings.REPRO_DEFAULT_OS
    azure = spec.get("azure", True)
    if not isinstance(azure, bool):
        errors.append("azure: must be true or false")
        azure = True
    if ps and (os_name != settings.REPRO_DEFAULT_OS or not azure):
        errors.append("os and azure: only supported for az specs")
    environment, install, os_name = _validate_environment(spec, os_name, azure, ps, errors)
    kind = (settings.REPRO_ENVIRONMENTS.get(environment) or {}).get("kind")
    if ps:
        shells = ()
    elif kind == "container":
        shells = settings.REPRO_CONTAINER_SHELLS
    elif kind == "vm":
        shells = settings.REPRO_VM_SHELLS
    else:
        shells = settings.REPRO_SHELLS[os_name]
    setup = _validate_steps(spec.get("setup"), "setup", ps, errors, shells)
    repro = _validate_steps(spec.get("repro"), "repro", ps, errors, shells)
    if not isinstance(spec.get("repro"), list) or not spec.get("repro"):
        errors.append("repro: at least one step is required")

    module = spec.get("module")
    if not ps:
        if module is not None:
            errors.append("module: only allowed for pwsh-az specs")
    elif module is not None and (
        not isinstance(module, str) or not _PS_MODULE.match(module)
    ):
        errors.append("module: must be an Az module (for example Az.Storage)")
    else:
        repro_modules = [ps_cmdlet_module(step["cmdlet"]) for step in repro]
        if module is None and repro_modules:
            module = repro_modules[0]
            if module is None:
                errors.append("module: name the Az module that ships the first repro cmdlet")
        elif (module is not None and repro and module not in repro_modules
              and None not in repro_modules):
            errors.append(
                "module: must be the module of at least one repro cmdlet"
            )

    observed = spec.get("observed_in_issue")
    observed_normalized = None
    if not isinstance(observed, dict) or not observed:
        errors.append(
            "observed_in_issue: required (exit_code, error_substring or "
            "output_substring) to define what `reproduced` means"
        )
    else:
        observed_normalized = _validate_expect(
            observed, "observed_in_issue", errors, _OBSERVED_KEYS,
        )

    if input_file is not None and not _uses_file_placeholder(setup + repro):
        errors.append("input_file: no step uses {file}")

    if errors:
        return {"valid": False, "errors": errors, "spec": None,
                "spec_hash": None}
    normalized = {
        "schema_version": settings.REPRO_SCHEMA_VERSION,
        "issue": issue,
        "tool": tool,
        "versions": versions,
        "location": location,
        "setup": setup,
        "repro": repro,
        "observed_in_issue": observed_normalized,
        "timeout_minutes": timeout,
    }
    if reported_version is not None:
        normalized["reported_version"] = reported_version
    if ps:
        normalized["module"] = module
    if workdir_dirs:
        normalized["workdir_dirs"] = sorted(workdir_dirs)
    if input_file is not None:
        normalized["input_file"] = input_file
    if os_name != settings.REPRO_DEFAULT_OS:
        normalized["os"] = os_name
    if environment is not None:
        normalized["environment"] = environment
    if install is not None:
        normalized["install"] = install
    if not azure:
        normalized["azure"] = False
    return {
        "valid": True, "errors": [], "spec": normalized,
        "spec_hash": _hash_canonical(canonical_spec_json(normalized)),
    }


def canonical_spec_json(spec):
    """Canonical JSON text of a normalized spec (the hash input)."""
    return json.dumps(
        spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )


def _hash_canonical(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _require_valid(spec):
    result = validate_spec(spec)
    if not result["valid"]:
        raise ReproSpecError(result["errors"])
    return result


def spec_hash(spec):
    """SHA-256 of the normalized spec; raises ReproSpecError if the spec is invalid."""
    return _require_valid(spec)["spec_hash"]


def _derive_name(spec_digest, run_id, index):
    digest = hashlib.sha256(
        f"{spec_digest}:{run_id}:{index}".encode("utf-8")
    ).hexdigest()
    # 12 lowercase alphanumerics starting with a letter, valid for most resource types.
    return f"xr{digest[:10]}"


def reproduction_resource_group(issue, run_id):
    """Per-run resource group xea-repro-<repo>-<number>-<run>."""
    match = _ISSUE.match(issue or "")
    if not match:
        raise ValueError("issue must be `Azure/<repo>#<number>`")
    repo = re.sub(r"[^a-z0-9-]", "-", match.group(1).split("/", 1)[1].lower())
    run = re.sub(r"[^A-Za-z0-9-]", "-", str(run_id))[:20]
    return (
        f"{settings.REPRO_RESOURCE_GROUP_PREFIX}-{repo}-{match.group(2)}-{run}"
    )[:90]


def placeholder_values(spec_digest, run_id, *, resource_group, location,
                       subscription_id=None, password=None, file_path=None):
    """Values for resolve_placeholders.

    Names come from the spec hash and run id, so re-runs reuse them and runs never collide.
    """
    values = {
        f"name{i}": _derive_name(spec_digest, run_id, i)
        for i in range(1, settings.REPRO_MAX_NAME_PLACEHOLDERS + 1)
    }
    values["name"] = values["name1"]
    values["rg"] = resource_group
    values["location"] = location
    for key, value in (("sub", subscription_id), ("password", password),
                       ("file", file_path)):
        if value is not None:
            values[key] = value
    return values


def _resolve_text(text, values, strict, missing):
    def replace(match):
        key = match.group(1)
        if key in values:
            return str(values[key])
        missing.add(key)
        return match.group(0)
    return _PLACEHOLDER.sub(replace, text)


def resolve_placeholders(spec, values, *, strict=True):
    """Copy of a normalized spec with step placeholders replaced.

    observed_in_issue and expect stay literal; strict raises on a placeholder without a value.
    """
    missing = set()

    def resolve(value):
        if isinstance(value, str):
            return _resolve_text(value, values, strict, missing)
        if isinstance(value, list):
            return [resolve(item) for item in value]
        return value

    resolved = json.loads(json.dumps(spec))
    for name in ("setup", "repro"):
        for step in resolved.get(name) or []:
            if "argv" in step:
                step["argv"] = [resolve(token) for token in step["argv"]]
            if "parameters" in step:
                step["parameters"] = {
                    key: resolve(value)
                    for key, value in step["parameters"].items()
                }
    if resolved.get("input_file"):
        resolved["input_file"]["content"] = resolve(
            resolved["input_file"]["content"]
        )
    if strict and missing:
        raise ReproSpecError([
            f"placeholders without values: {', '.join(sorted(missing))}"
        ])
    return resolved
