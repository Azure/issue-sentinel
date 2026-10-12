# GENERATED FILE - DO NOT EDIT.
# Vendored from x-engineering-agent `src/tools/live_tests/reproduction.py` by
# `scripts/sync_issue_sentinel_repro.py`; edit the source and re-run it.
"""Vendored ReproSpec validation, hashing and placeholders.

Identical to the validation sections of
``x_engineering_agent.tools.live_tests.reproduction`` (see that
module docstring for the ReproSpec v1 contract); dispatch code is
omitted.
"""

import hashlib
import json
import re
from urllib.parse import urlsplit

import repro_policy as settings
from repro_sensitive_data import scan_sensitive_content

# Repository kinds and Agent forks from x_engineering_agent REPO_PROFILES.
REPO_PROFILES = {
    'Azure/azclips': {'kind': 'dotnet-cli', 'agent_fork': 'Azure/azclips'},
    'Azure/azure-cli': {'kind': 'cli', 'agent_fork': 'a0x1ab/azure-cli'},
    'Azure/azure-cli-extensions': {'kind': 'cli-ext', 'agent_fork': 'a0x1ab/azure-cli-extensions'},
    'Azure/azure-powershell': {'kind': 'powershell', 'agent_fork': 'a0x1ab/azure-powershell'},
    'Azure/terraform-provider-azapi': {'kind': 'terraform-provider', 'agent_fork': None},
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
        "module": {"type": "string", "pattern": r"^Az\.[A-Za-z]{2,40}$"},
        "location": {"enum": list(settings.REPRO_ALLOWED_LOCATIONS)},
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
    },
    "$defs": {
        "step": {
            "type": "object",
            "oneOf": [
                {"required": ["argv"]},
                {"required": ["cmdlet", "parameters"]},
            ],
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"}},
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
    r"^/subscriptions/\{sub\}/resourcegroups/\{rg\}(?:/[^/?#]+)*$", re.I,
)
_ARM_URL = re.compile(
    r"^(?:https://management\.azure\.com)?"
    r"/subscriptions/\{sub\}/resourcegroups/\{rg\}(?:/[A-Za-z0-9._{}-]+)*"
    r"(?:\?api-version=\d{4}-\d{2}-\d{2}(?:-preview)?)?$",
    re.I,
)
_API_VERSION_PARAM = re.compile(r"^api-version=\d{4}-\d{2}-\d{2}(?:-preview)?$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_LOCAL_PATH = re.compile(r"^(?:/|~|[A-Za-z]:[\\/])|(?:^|[\\/])\.\.(?:[\\/]|$)")
_PS_CMDLET = re.compile(r"^([A-Z][a-z]+)-Az([A-Za-z][A-Za-z0-9]{1,80})$")
_PS_PARAMETER = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_PS_MODULE = re.compile(r"^Az\.[A-Za-z]{2,40}$")
_TOP_KEYS = frozenset({
    "schema_version", "issue", "tool", "versions", "reported_version",
    "module",
    "location", "setup", "repro", "observed_in_issue", "timeout_minutes",
})
_OBSERVED_KEYS = frozenset({"exit_code", "error_substring", "output_substring"})
_EXPECT_KEYS = frozenset({"exit_code", "error_substring"})
_REST_FLAGS = frozenset({
    "--method", "-m", "--url", "--uri", "-u", "--uri-parameters",
    "--url-parameters", "--query", "-o", "--output", "--debug", "--verbose",
    "--only-show-errors",
})
_QUERY_FLAGS = frozenset({"--query"})
_OUTPUT_FLAGS = frozenset({"-o", "--output"})
_NAME_FLAGS = frozenset({"-n", "--name"})
_MAX_SPEC_JSON_CHARS = 20_000


class ReproSpecError(ValueError):
    """A ReproSpec failed validation; ``errors`` lists every problem."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("Invalid ReproSpec: " + "; ".join(self.errors))


# Value checks --------------------------------------------------------------

def _strip_placeholders(value):
    return _PLACEHOLDER.sub("", value)


def _host_allowed(host):
    host = (host or "").lower()
    if host in settings.REPRO_ALLOWED_IMAGE_HOSTS:
        return True
    label, _, suffix = host.partition(".")
    return bool(
        re.fullmatch(r"\{name[1-9]?\}", label)
        and f".{suffix}" in settings.REPRO_PLACEHOLDER_HOST_SUFFIXES
    )


def _check_hosts(value, loc, errors):
    """URLs and host names may only point at resources the run creates."""
    if _BARE_SCHEME.search(value):
        errors.append(f"{loc}: URL schemes are not allowed")
        return
    for match in _URL.finditer(value):
        url = match.group(0)
        if not url.lower().startswith("https://"):
            errors.append(f"{loc}: only https URLs are allowed")
            return
        netloc = urlsplit(url).netloc
        if "@" in netloc or ":" in netloc or not _host_allowed(netloc):
            errors.append(
                f"{loc}: URL host is not allowed; URLs may only target "
                "resources created by the run ({nameN}.<azure suffix>)"
            )
            return
    for match in _HOST.finditer(value):
        if not _host_allowed(match.group(1)):
            errors.append(
                f"{loc}: host `{match.group(1).lower()[:80]}` is not allowed; "
                "only resources created by the run ({nameN}.<azure suffix>)"
            )
            return


def _looks_like_key(value):
    for match in _KEY_RUN.finditer(_strip_placeholders(value)):
        run = match.group(0)
        if (any(c.isdigit() for c in run) and any(c.islower() for c in run)
                and any(c.isupper() for c in run)):
            return True
    return False


def _check_sensitive(value, loc, errors):
    if _GUID.search(value):
        errors.append(
            f"{loc}: literal GUIDs (subscription, tenant or object IDs) are "
            "not allowed; use placeholders"
        )
    if _looks_like_key(value):
        errors.append(f"{loc}: value looks like a key or token")
    scan = scan_sensitive_content([{"location": loc, "text": value}])
    if scan["blocked"]:
        categories = sorted({f["category"] for f in scan["findings"]})
        errors.append(
            f"{loc}: sensitive data detected ({', '.join(categories)})"
        )


def _check_value(value, loc, errors):
    """Checks shared by every az argument value and PowerShell string."""
    if not isinstance(value, str):
        errors.append(f"{loc}: must be a string")
        return
    if not value:
        errors.append(f"{loc}: empty value")
        return
    if len(value) > settings.REPRO_MAX_ARG_CHARS:
        errors.append(
            f"{loc}: longer than {settings.REPRO_MAX_ARG_CHARS} characters"
        )
        return
    if _CONTROL.search(value):
        errors.append(f"{loc}: control characters or newlines are not allowed")
        return
    if value.startswith("@"):
        errors.append(f"{loc}: `@file` arguments are not allowed")
        return
    for name in ("password", "file"):
        if "{" + name + "}" in value:
            errors.append(
                f"{loc}: {{{name}}} is only allowed as the whole value of a "
                f"{name} argument"
            )
    rest = _strip_placeholders(value)
    if "{" in rest or "}" in rest:
        errors.append(
            f"{loc}: braces are only allowed in placeholders "
            f"({', '.join('{' + p + '}' for p in PLACEHOLDERS)}); script "
            "blocks and templates are not allowed"
        )
    if _SHELL_META.search(rest):
        errors.append(
            f"{loc}: shell metacharacters, quotes and variable expansion "
            "are not allowed"
        )
    if "/subscriptions/" in value.lower():
        if not _RESOURCE_ID.match(value) or _DOT_SEGMENT.search(value):
            errors.append(
                f"{loc}: resource IDs must start with "
                "/subscriptions/{sub}/resourceGroups/{rg}"
            )
    elif "{sub}" in value:
        errors.append(
            f"{loc}: {{sub}} is only allowed inside "
            "/subscriptions/{sub}/resourceGroups/{rg}"
        )
    elif _LOCAL_PATH.search(value):
        errors.append(f"{loc}: local file paths are not allowed")
    _check_hosts(value, loc, errors)
    _check_sensitive(value, loc, errors)


def _check_query(value, loc, errors):
    """JMESPath for ``--query``: argv-only, so pipes and filters are fine."""
    if not isinstance(value, str) or not value:
        errors.append(f"{loc}: must be a non-empty string")
        return
    if len(value) > settings.REPRO_MAX_QUERY_CHARS:
        errors.append(
            f"{loc}: longer than {settings.REPRO_MAX_QUERY_CHARS} characters"
        )
    if _CONTROL.search(value):
        errors.append(f"{loc}: control characters or newlines are not allowed")
    if value.startswith("@"):
        errors.append(f"{loc}: `@file` arguments are not allowed")
    if _QUERY_FORBIDDEN.search(value):
        errors.append(
            f"{loc}: `;`, `$`, `%` and backslashes are not allowed in --query"
        )
    _check_hosts(value, loc, errors)
    _check_sensitive(value, loc, errors)


def _check_exact(value, expected, loc, errors, what):
    if value != expected:
        errors.append(f"{loc}: {what} must be {expected}")


def _check_sku(value, loc, errors):
    if not isinstance(value, str) or (
        value.casefold() not in settings.REPRO_ALLOWED_SKUS
    ):
        errors.append(f"{loc}: SKU/size `{value}` is not in the cheap-SKU allowlist")


def _check_count(value, loc, errors):
    try:
        count = int(value)
    except (TypeError, ValueError):
        errors.append(f"{loc}: count must be an integer")
        return
    if not 0 <= count <= settings.REPRO_MAX_INSTANCE_COUNT:
        errors.append(
            f"{loc}: count must be at most {settings.REPRO_MAX_INSTANCE_COUNT}"
        )


def _check_name(value, loc, errors):
    _check_value(value, loc, errors)
    if isinstance(value, str) and not _SAFE_NAME.match(
        _PLACEHOLDER.sub("x", value)
    ):
        errors.append(
            f"{loc}: names must be placeholders ({{nameN}}) or simple "
            "letters, digits, `.`, `_` and `-`"
        )


def _check_text(value, loc, errors):
    """Single-line issue text compared as a fixed string by the workflow."""
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{loc}: must be a non-empty string")
        return
    if len(value) > settings.REPRO_MAX_TEXT_CHARS:
        errors.append(
            f"{loc}: longer than {settings.REPRO_MAX_TEXT_CHARS} characters"
        )
    if _CONTROL.search(value):
        errors.append(f"{loc}: control characters or newlines are not allowed")
    _check_sensitive(value, loc, errors)


# az steps ------------------------------------------------------------------

def _special_flag_names():
    return (
        settings.REPRO_AZ_DENIED_ARGUMENTS
        | settings.REPRO_AZ_FILE_ARGUMENTS
        | settings.REPRO_AZ_PASSWORD_ARGUMENTS
    )


def _parse_flags(tokens, loc, errors):
    """Split ``tokens`` (after the command path) into ``[(flag, [values])]``."""
    flags = []
    for index, token in enumerate(tokens):
        tloc = f"{loc}[{index}]"
        if token.startswith("-") and not _NUMBER.match(token):
            flag, eq, value = token.partition("=")
            if not (_LONG_FLAG.match(flag) or _SHORT_FLAG.match(flag)):
                errors.append(
                    f"{tloc}: malformed argument (combined short flags and "
                    "attached values are not allowed)"
                )
                flags.append((flag, []))
                continue
            flags.append((flag, [value] if eq else []))
        elif flags:
            flags[-1][1].append(token)
        else:
            errors.append(f"{tloc}: unexpected positional argument")
    return flags


def _command_allowed(path):
    def matches(rule):
        return tuple(path[:len(rule)]) == rule
    if any(matches(rule) for rule in settings.REPRO_AZ_DENIED_COMMANDS):
        return False
    if any(token in settings.REPRO_AZ_DENIED_COMMAND_TOKENS for token in path):
        return False
    return any(matches(rule) for rule in settings.REPRO_AZ_ALLOWED_COMMANDS)


def _validate_rest(path, flags, loc, errors):
    """``az rest`` is allowed only as GET on ARM inside the run's RG."""
    if path != ["rest"]:
        errors.append(f"{loc}: `az rest` takes no subcommands")
    urls = []
    for flag, values in flags:
        floc = f"{loc} {flag}"
        if flag not in _REST_FLAGS:
            errors.append(f"{floc}: argument not allowed for `az rest`")
            continue
        if flag in ("--method", "-m"):
            if [v.lower() for v in values] != ["get"]:
                errors.append(f"{floc}: `az rest` is limited to GET")
        elif flag in ("--url", "--uri", "-u"):
            urls.extend(values)
            for value in values:
                if (not isinstance(value, str) or not _ARM_URL.match(value)
                        or _DOT_SEGMENT.search(value)
                        or "{" in _strip_placeholders(value)
                        or "}" in _strip_placeholders(value)):
                    errors.append(
                        f"{floc}: `az rest` URLs must be "
                        "https://management.azure.com/subscriptions/{sub}/"
                        "resourceGroups/{rg}/..."
                    )
                else:
                    _check_sensitive(value, floc, errors)
        elif flag in ("--uri-parameters", "--url-parameters"):
            for value in values:
                if not _API_VERSION_PARAM.match(value):
                    errors.append(f"{floc}: only api-version=YYYY-MM-DD is allowed")
        elif flag in _QUERY_FLAGS:
            for value in values:
                _check_query(value, floc, errors)
        elif flag in _OUTPUT_FLAGS:
            if len(values) != 1 or values[0] not in settings.REPRO_AZ_OUTPUT_FORMATS:
                errors.append(f"{floc}: unsupported output format")
        elif values:
            errors.append(f"{floc}: takes no value")
    if len(urls) != 1:
        errors.append(f"{loc}: `az rest` needs exactly one --url")


def _validate_flag(flag, values, floc, errors):
    if flag in settings.REPRO_AZ_DENIED_ARGUMENTS:
        errors.append(f"{floc}: argument is not allowed")
        return
    if flag not in _special_flag_names() and len(flag) > 2 and (
        flag not in settings.REPRO_AZ_PREFIX_SAFE_ARGUMENTS
    ) and any(
        name.startswith(flag) for name in _special_flag_names()
    ):
        errors.append(
            f"{floc}: abbreviation of a restricted argument is not allowed"
        )
        return
    if flag in settings.REPRO_AZ_FILE_ARGUMENTS:
        _check_exact(values, ["{file}"], floc, errors, "the value")
    elif flag in settings.REPRO_AZ_PASSWORD_ARGUMENTS:
        _check_exact(values, ["{password}"], floc, errors, "the value")
    elif (flag in settings.REPRO_AZ_RESOURCE_GROUP_ARGUMENTS
          or flag.endswith("-resource-group")):
        _check_exact(values, ["{rg}"], floc, errors, "the resource group")
    elif flag in settings.REPRO_AZ_LOCATION_ARGUMENTS:
        _check_exact(values, ["{location}"], floc, errors, "the location")
    elif flag in settings.REPRO_AZ_SKU_ARGUMENTS:
        if len(values) != 1:
            errors.append(f"{floc}: needs exactly one value")
        for value in values:
            _check_sku(value, floc, errors)
    elif flag in settings.REPRO_AZ_COUNT_ARGUMENTS:
        if len(values) != 1:
            errors.append(f"{floc}: needs exactly one value")
        for value in values:
            _check_count(value, floc, errors)
    elif flag in _OUTPUT_FLAGS:
        if len(values) != 1 or values[0] not in settings.REPRO_AZ_OUTPUT_FORMATS:
            errors.append(f"{floc}: unsupported output format")
    elif flag in _QUERY_FLAGS:
        if len(values) != 1:
            errors.append(f"{floc}: needs exactly one value")
        for value in values:
            _check_query(value, floc, errors)
    elif flag in _NAME_FLAGS or (
        flag.endswith("-name") and flag != "--sku-name"
    ):
        for value in values:
            _check_name(value, floc, errors)
    else:
        for value in values:
            _check_value(value, floc, errors)


def _validate_az_step(step, loc, errors):
    argv = step.get("argv")
    if not isinstance(argv, list) or not all(isinstance(t, str) for t in argv):
        errors.append(f"{loc}.argv: must be a list of strings")
        return None
    if len(argv) < 2 or argv[0] != "az":
        errors.append(f"{loc}.argv: must start with `az` and a command")
        return None
    if len(argv) > settings.REPRO_MAX_ARGS_PER_STEP:
        errors.append(
            f"{loc}.argv: more than {settings.REPRO_MAX_ARGS_PER_STEP} tokens"
        )
        return None
    tokens = argv[1:]
    path = []
    for token in tokens:
        if token.startswith("-"):
            break
        path.append(token)
    if not path:
        errors.append(f"{loc}.argv: missing command")
        return None
    bad = [t for t in path if not _COMMAND_TOKEN.match(t)]
    if bad:
        errors.append(
            f"{loc}.argv: command tokens must be lowercase words; shell "
            "metacharacters and positional values are not allowed"
        )
        for token in bad:
            _check_value(token, f"{loc}.argv", errors)
        return None
    flags = _parse_flags(tokens[len(path):], f"{loc}.argv", errors)
    command = " ".join(["az", *path])
    if path[0] == "rest":
        _validate_rest(path, flags, f"{loc} `{command}`", errors)
    elif not _command_allowed(path):
        errors.append(
            f"{loc}: `{command}` is not an allowed reproduction command"
        )
    else:
        for flag, values in flags:
            _validate_flag(flag, values, f"{loc} `{command}` {flag}", errors)
    return {"argv": list(argv)}


# PowerShell steps ----------------------------------------------------------

def _ps_special_parameters():
    return (
        settings.REPRO_PS_DENIED_PARAMETERS | settings.REPRO_PS_FILE_PARAMETERS
    )


def _ps_noun_prefix(noun):
    prefixes = sorted(
        (p for p in settings.REPRO_PS_ALLOWED_NOUN_PREFIXES
         if noun.casefold().startswith(p.casefold())),
        key=len, reverse=True,
    )
    return prefixes[0] if prefixes else None


def ps_cmdlet_module(cmdlet):
    """Az module (``Az.<X>``) that ships an allowlisted cmdlet, else None."""
    match = _PS_CMDLET.match(cmdlet) if isinstance(cmdlet, str) else None
    prefix = _ps_noun_prefix(match.group(2)) if match else None
    return settings.REPRO_PS_NOUN_MODULES.get(prefix) if prefix else None


def _check_ps_cmdlet(cmdlet, loc, errors):
    match = _PS_CMDLET.match(cmdlet) if isinstance(cmdlet, str) else None
    if not match:
        errors.append(f"{loc}.cmdlet: must be a `Verb-Az<Noun>` cmdlet name")
        return False
    verb, noun = match.groups()
    if verb not in settings.REPRO_PS_ALLOWED_VERBS:
        errors.append(f"{loc}.cmdlet: verb `{verb}` is not allowed")
        return False
    prefix = _ps_noun_prefix(noun)
    if not prefix or not ps_cmdlet_module(cmdlet):
        errors.append(f"{loc}.cmdlet: `{cmdlet}` is not in an allowed module")
        return False
    verbs = settings.REPRO_PS_ALLOWED_NOUN_PREFIXES[prefix]
    if verbs is not None and verb not in verbs:
        errors.append(f"{loc}.cmdlet: `{cmdlet}` is read-only (Get) here")
        return False
    if any(re.search(p, f"Az{noun}")
           for p in settings.REPRO_PS_DENIED_NOUN_PATTERNS):
        errors.append(f"{loc}.cmdlet: `{cmdlet}` is denied")
        return False
    return True


def _check_ps_value(key, value, loc, errors):
    lowered = key.casefold()
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        if lowered in settings.REPRO_PS_COUNT_PARAMETERS:
            _check_count(value, loc, errors)
        elif abs(value) > 10 ** 6:
            errors.append(f"{loc}: number out of range")
        return
    if isinstance(value, list):
        if len(value) > settings.REPRO_MAX_LIST_ITEMS:
            errors.append(f"{loc}: more than {settings.REPRO_MAX_LIST_ITEMS} items")
            return
        for index, item in enumerate(value):
            if isinstance(item, (list, dict)):
                errors.append(f"{loc}[{index}]: nested values are not allowed")
            else:
                _check_ps_value(key, item, f"{loc}[{index}]", errors)
        return
    if not isinstance(value, str):
        errors.append(
            f"{loc}: only strings, numbers, booleans and flat lists are "
            "allowed (no script blocks, hashtables or null)"
        )
        return
    if lowered in settings.REPRO_PS_FILE_PARAMETERS:
        _check_exact(value, "{file}", loc, errors, "the value")
    elif any(word in lowered for word in ("pass", "secret", "pwd")):
        _check_exact(value, "{password}", loc, errors, "the value")
    elif lowered.endswith("resourcegroupname"):
        _check_exact(value, "{rg}", loc, errors, "the resource group")
    elif lowered == "location":
        _check_exact(value, "{location}", loc, errors, "the location")
    elif lowered in settings.REPRO_PS_SKU_PARAMETERS:
        _check_sku(value, loc, errors)
    elif lowered in settings.REPRO_PS_COUNT_PARAMETERS:
        _check_count(value, loc, errors)
    elif lowered.endswith("name"):
        _check_name(value, loc, errors)
    else:
        _check_value(value, loc, errors)


def _validate_ps_step(step, loc, errors):
    cmdlet = step.get("cmdlet")
    parameters = step.get("parameters")
    if not _check_ps_cmdlet(cmdlet, loc, errors):
        return None
    if not isinstance(parameters, dict):
        errors.append(f"{loc}.parameters: must be an object (hashtable)")
        return None
    if len(parameters) > settings.REPRO_MAX_PS_PARAMETERS:
        errors.append(
            f"{loc}.parameters: more than {settings.REPRO_MAX_PS_PARAMETERS}"
        )
        return None
    seen = set()
    for key, value in parameters.items():
        ploc = f"{loc}.parameters.{str(key)[:40]}"
        if not isinstance(key, str) or not _PS_PARAMETER.match(key):
            errors.append(f"{ploc}: invalid parameter name")
            continue
        lowered = key.casefold()
        if lowered in seen:
            errors.append(f"{ploc}: duplicate parameter")
            continue
        seen.add(lowered)
        if lowered in settings.REPRO_PS_DENIED_PARAMETERS:
            errors.append(f"{ploc}: parameter is not allowed")
            continue
        if lowered not in _ps_special_parameters() and any(
            name.startswith(lowered) for name in _ps_special_parameters()
        ):
            errors.append(
                f"{ploc}: abbreviation of a restricted parameter is not allowed"
            )
            continue
        _check_ps_value(key, value, ploc, errors)
    return {"cmdlet": cmdlet, "parameters": dict(parameters)}


# Spec ----------------------------------------------------------------------

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


def _validate_steps(steps, name, ps, errors):
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
        allowed = {"cmdlet", "parameters", "expect"} if ps else {"argv", "expect"}
        unknown = sorted(set(step) - allowed)
        if unknown:
            errors.append(
                f"{loc}: unknown keys {', '.join(map(str, unknown))} "
                f"(steps for this tool use {', '.join(sorted(allowed))})"
            )
            continue
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
    kind = (REPO_PROFILES.get(repository) or {}).get("kind")
    if tool == "pwsh-az":
        if kind != "powershell":
            errors.append("tool: pwsh-az reproduces Azure PowerShell issues only")
    elif kind not in ("cli", "cli-ext"):
        errors.append(f"tool: `{tool}` reproduces Azure CLI issues only")


def validate_spec(spec):
    """Validate and normalise a ReproSpec without touching the network.

    ``spec`` is a dict or its JSON text. Returns ``{"valid": bool,
    "errors": [str], "spec": normalized dict | None, "spec_hash": str |
    None}``. Errors name the offending location (for example
    ``repro[0] `az rest` --url``) but never echo full argument values.
    The normalized spec fills defaults (schema_version, versions in
    canonical order, location, timeout_minutes, setup) so equal intents
    hash equally.
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
    if location not in settings.REPRO_ALLOWED_LOCATIONS:
        errors.append(
            f"location: must be one of {list(settings.REPRO_ALLOWED_LOCATIONS)}"
        )

    timeout = spec.get(
        "timeout_minutes", settings.REPRO_DEFAULT_TIMEOUT_MINUTES,
    )
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not (
        1 <= timeout <= settings.REPRO_MAX_TIMEOUT_MINUTES
    ):
        errors.append(
            f"timeout_minutes: must be 1..{settings.REPRO_MAX_TIMEOUT_MINUTES}"
        )

    ps = tool == "pwsh-az"
    setup = _validate_steps(spec.get("setup"), "setup", ps, errors)
    repro = _validate_steps(spec.get("repro"), "repro", ps, errors)
    if not isinstance(spec.get("repro"), list) or not spec.get("repro"):
        errors.append("repro: at least one step is required")
    total = sum(
        len(spec.get(name)) for name in ("setup", "repro")
        if isinstance(spec.get(name), list)
    )
    if total > settings.REPRO_MAX_STEPS:
        errors.append(f"steps: at most {settings.REPRO_MAX_STEPS} in total")

    module = spec.get("module")
    if not ps:
        if module is not None:
            errors.append("module: only allowed for pwsh-az specs")
    elif module is not None and (
        not isinstance(module, str) or not _PS_MODULE.match(module)
        or module not in settings.REPRO_PS_ALLOWED_MODULES
    ):
        errors.append(
            "module: must be an allowlisted Az module (for example Az.Storage)"
        )
    else:
        repro_modules = [ps_cmdlet_module(step["cmdlet"]) for step in repro]
        if module is None and repro_modules:
            module = repro_modules[0]
        elif module is not None and repro and module not in repro_modules:
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
    return {
        "valid": True, "errors": [], "spec": normalized,
        "spec_hash": _hash_canonical(canonical_spec_json(normalized)),
    }


def canonical_spec_json(spec):
    """Canonical JSON text of an already normalized spec (hash input)."""
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
    """Deterministic SHA-256 hex of the normalized spec.

    Key order, omitted defaults and version order do not change the hash.
    Raises ``ReproSpecError`` when the spec is invalid.
    """
    return _require_valid(spec)["spec_hash"]


# Placeholders ----------------------------------------------------------------

def _derive_name(spec_digest, run_id, index):
    digest = hashlib.sha256(
        f"{spec_digest}:{run_id}:{index}".encode("utf-8")
    ).hexdigest()
    # 12 lowercase alphanumerics, starting with a letter: valid for storage
    # accounts, key vaults, web apps and most other resource types.
    return f"xr{digest[:10]}"


def reproduction_resource_group(issue, run_id):
    """Per-run resource group ``xea-repro-<repo>-<number>-<run>``."""
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
    """Values for ``resolve_placeholders``; names are deterministic.

    ``{nameN}`` derives from the spec hash and run id, so re-running the
    same run reuses the same names and different runs never collide.
    ``{name}`` is an alias of ``{name1}``. ``{sub}``, ``{password}`` and
    ``{file}`` are only known inside the workflow; when omitted they stay
    unresolved and ``resolve_placeholders(strict=False)`` keeps them.
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
    """Return a copy of a normalized spec with step placeholders replaced.

    Only ``argv`` tokens and PowerShell parameter values are resolved;
    ``observed_in_issue`` and ``expect`` stay literal. With ``strict`` a
    placeholder without a value raises ``ReproSpecError``.
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
    if strict and missing:
        raise ReproSpecError([
            f"placeholders without values: {', '.join(sorted(missing))}"
        ])
    return resolved
