"""Parser definitions and their mapping to an Evidence directory."""

import re
import runpy
import shlex
from dataclasses import dataclass
from pathlib import Path
from catalog import _identifier

PARSERS = {
    "windows": {
        "dissectable": [
            {
                "category": "logs",
                "functions": [
                    "evt",
                    "evtx",
                    "scraped_evtx"
                ]
            },
            {
                "category": "persistence",
                "functions": [
                    "tasks",
                    "runkeys",
                    "services",
                    "cim"
                ]
            },
            {
                "category": "config",
                "functions": [
                    "regf",
                    "sam",
                    "applications",
                    "clsid"
                ]
            },
            {
                "category": "filesystems",
                "functions": [
                    "recyclebin"
                ]
            },
            {
                "category": "amcache",
                "functions": [
                    "amcache.application_files",
                    "amcache.applaunches",
                    "amcache.device_containers",
                    "amcache.drivers",
                    "amcache.files",
                    "amcache.general",
                    "amcache.shortcuts"
                ]
            },
            {
                "category": "execution",
                "functions": [
                    "shimcache",
                    "shellbags",
                    "userassist",
                    "bam",
                    "prefetch",
                    "lnk",
                    "jumplist.automatic_destination",
                    "jumplist.custom_destination",
                    "powershell_history"
                ]
            },
            {
                "category": "ual",
                "functions": [
                    "ual.client_access",
                    "ual.domains_seen",
                    "ual.role_access",
                    "ual.system_identities",
                    "ual.virtual_machines"
                ]
            },
            {
                "category": "defender",
                "functions": [
                    "defender.exclusions",
                    "defender.mpcmdrun",
                    "defender.mplog"
                ]
            },
            {
                "category": "mru",
                "functions": [
                    "mru.acmru",
                    "mru.lastvisited",
                    "mru.msoffice",
                    "mru.mstsc",
                    "mru.networkdrive",
                    "mru.opensave",
                    "mru.recentdocs",
                    "mru.run"
                ]
            },
            {
                "category": "firewall",
                "functions": [
                    "firewall.rules",
                    "firewall.logs"
                ]
            },
            {
                "category": "browser",
                "functions": [
                    "browser.downloads",
                    "browser.history",
                    "browser.extensions",
                    "browser.cookies",
                    "browser.passwords"
                ]
            },
            {
                "category": "webserver",
                "functions": [
                    "webserver.logs"
                ]
            },
            {
                "category": "sru",
                "functions": [
                    "sru.application",
                    "sru.application_timeline",
                    "sru.energy_estimator",
                    "sru.energy_usage",
                    "sru.energy_usage_lt",
                    "sru.network_connectivity",
                    "sru.network_data",
                    "sru.push_notification",
                    "sru.sdp_cpu_provider",
                    "sru.sdp_network_provider",
                    "sru.sdp_physical_disk_provider",
                    "sru.sdp_volume_provider",
                    "sru.vfu",
                ]
            }
        ],
        "non_dissectable": [
            {
                "name": "mft",
                "category": "filesystems",
                "output": "warehouse/filesystems/mft.tsv",
                "commandline": ["ntfs_parser", "--mft-timeline", "01_target/C/$MFT", "{output}"],
                "duckdb_view_query": (
                    "CREATE OR REPLACE VIEW mft AS "
                    "SELECT Timestamp AS ts, "
                    f"{_identifier("Timestamp Type")} AS ts_description, "
                    f"Source AS record_type, "
                    f"{_identifier("MFT reference number")} AS mft_ref_num,"
                    f"{_identifier("Is in use")} AS is_inuse, "
                    f"{_identifier("Is directory")} AS is_dir, "
                    f"{_identifier("Log file sequence number")} AS LSN, "
                    "Path AS path,"
                    f"{_identifier("$SI USN value")} AS USN, "
                    f"{_identifier("File size")} AS size, "
                    f"{_identifier("ADS list" )} AS ADS"
                    " FROM read_csv_auto({output_sql}, header = true, "
                    "types = {'MFT reference number': 'UBIGINT', '$SI USN value': 'UBIGINT'})"
                ),
            },
            # {
            #     "name": "usn",
            #     "category": "filesystems",
            #     "output": "warehouse/filesystems/usn.tsv",
            #     "commandline": ["ntfs_parser", "--usn", "01_target/C/$MFT", "01_target/C/$Extend/$J", "{output}"],
            #     "duckdb_view_query": ""
            # },
        ],
    },
    "linux": {},
}

EXCLUDE_KEYS = (
    "hostname", "domain", "_source", "_classification", "_generated", "_version",
    "_type", "_recorddescriptor",
)


@dataclass(frozen=True)
class Parser:
    name: str
    category: str
    output: Path | None
    dissectable: bool = False
    command: tuple[str, ...] = ()
    view_query: str = ""


def _safe_name(name: str) -> str:
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name) is None:
        raise ValueError(f"Invalid function or category name {name!r}")
    return name


def get_parsers(evidence: Path, os_name: str, config_path: Path | None) -> list[Parser]:
    if config_path is None:
        local_config = evidence / "parsers.py"
        config_path = local_config if local_config.is_file() else None
    config = PARSERS if config_path is None else runpy.run_path(str(config_path))["PARSERS"]
    if os_name not in config:
        raise ValueError(f"PARSERS has no profile for OS {os_name!r}")

    profile = config[os_name]
    parsers = []
    for group in profile.get("dissectable", []):
        category = _safe_name(group["category"])
        for function in group["functions"]:
            name = _safe_name(function)
            output = evidence / "warehouse" / category / f"{name}.jsonl"
            parsers.append(Parser(name, category, output, dissectable=True))

    for entry in profile.get("non_dissectable", []):
        name = _safe_name(entry["name"])
        category = _safe_name(entry.get("category", "main"))
        command = entry.get("commandline", "")
        if isinstance(command, str):
            command = shlex.split(command)
        if not isinstance(command, (list, tuple)) or any(not isinstance(arg, str) for arg in command):
            raise ValueError(f"{name}: commandline must be a string or a list of strings")
        output = evidence / entry["output"] if entry.get("output") else None
        query = entry.get("duckdb_view_query", "").strip()
        if output is None and ("{output}" in command or "{output_sql}" in query):
            raise ValueError(f"{name}: set output before using an output path placeholder")
        parsers.append(Parser(name, category, output, command=tuple(command), view_query=query))

    names = set()
    outputs = set()
    for parser in parsers:
        name = parser.name.casefold()
        if name in names:
            raise ValueError(f"Duplicate parser name {parser.name!r} in the OS profile")
        names.add(name)
        if parser.output is not None:
            output = parser.output.resolve()
            if output in outputs:
                raise ValueError(f"Multiple parsers write to {output}")
            outputs.add(output)
    return parsers
