"""Parser definitions and their mapping to an Evidence directory."""

import re
import runpy
import shlex
from dataclasses import dataclass
from pathlib import Path
from .utils import identifier

PARSERS = {
    "windows": {
        "dissectable": [
            {
                "category": "logs",
                "functions": [
                    {"name": "evt", "pinned_columns": ("EventID", "Provider_Name", "Channel")},
                    {"name": "evtx", "pinned_columns": ("EventID", "Provider_Name", "Channel")},
                    {"name": "scraped_evt", "pinned_columns": ("EventID", "Provider_Name", "Channel")},
                ]
            },
            {
                "category": "persistence",
                "functions": [
                    {"name": "tasks"},
                    {"name": "runkeys"},
                    {"name": "services"},
                    {"name": "cim"},
                ]
            },
            {
                "category": "config",
                "functions": [
                    {"name": "regf"},
                    {"name": "sam"},
                    {"name": "applications"},
                    {"name": "clsid"},
                ]
            },
            {
                "category": "filesystems",
                "functions": [
                    {"name": "recyclebin"}
                ]
            },
            {
                "category": "amcache",
                "functions": [
                    {"name": "amcache.application_files"},
                    {"name": "amcache.applaunches"},
                    {"name": "amcache.device_containers"},
                    {"name": "amcache.drivers"},
                    {"name": "amcache.files"},
                    {"name": "amcache.general"},
                    {"name": "amcache.shortcuts"}
                ]
            },
            {
                "category": "execution",
                "functions": [
                    {"name": "shimcache"},
                    {"name": "shellbags"},
                    {"name": "userassist"},
                    {"name": "bam"},
                    {"name": "prefetch"},
                    {"name": "lnk"},
                    {"name": "jumplist.automatic_destination"},
                    {"name": "jumplist.custom_destination"},
                    {"name": "powershell_history"}
                ]
            },
            {
                "category": "ual",
                "functions": [
                    {"name": "ual.client_access"},
                    {"name": "ual.domains_seen"},
                    {"name": "ual.role_access"},
                    {"name": "ual.system_identities"},
                    {"name": "ual.virtual_machines"}
                ]
            },
            {
                "category": "defender",
                "functions": [
                    {"name": "defender.exclusions"},
                    {"name": "defender.mpcmdrun"},
                    {"name": "defender.mplog"}
                ]
            },
            {
                "category": "mru",
                "functions": [
                    {"name": "mru.acmru"},
                    {"name": "mru.lastvisited"},
                    {"name": "mru.msoffice"},
                    {"name": "mru.mstsc"},
                    {"name": "mru.networkdrive"},
                    {"name": "mru.opensave"},
                    {"name": "mru.recentdocs"},
                    {"name": "mru.run"}
                ]
            },
            {
                "category": "firewall",
                "functions": [
                    {"name": "firewall.rules"},
                    {"name": "firewall.logs"}
                ]
            },
            {
                "category": "browser",
                "functions": [
                    {"name": "browser.downloads"},
                    {"name": "browser.history"},
                    {"name": "browser.extensions"},
                    {"name": "browser.cookies"},
                    {"name": "browser.passwords"}
                ]
            },
            {
                "category": "webserver",
                "functions": [
                    {"name": "webserver.access"},
                    {"name": "webserver.error"},
                    {"name": "webserver.hosts"},
                ]
            },
            {
                "category": "sru",
                "functions": [
                    {"name": "sru.application"},
                    {"name": "sru.application_timeline"},
                    {"name": "sru.energy_estimator"},
                    {"name": "sru.energy_usage"},
                    {"name": "sru.energy_usage_lt"},
                    {"name": "sru.network_connectivity"},
                    {"name": "sru.network_data"},
                    {"name": "sru.push_notification"},
                    {"name": "sru.sdp_cpu_provider"},
                    {"name": "sru.sdp_network_provider"},
                    {"name": "sru.sdp_physical_disk_provider"},
                    {"name": "sru.sdp_volume_provider"},
                    {"name": "sru.vfu"},
                ]
            },
            {
                "category": "ssh",
                "functions": [
                    {"name": "ssh.authroized_keys"},
                    {"name": "ssh.known_hosts"},
                    {"name": "opensshd.config"},
                    {"name": "putty.known_hosts"},
                    {"name": "putty.sessions"},
                ]
            },
            {
                "category": "vpn",
                "functions": [
                    {"name": "openvpn.config"},
                    {"name": "wireguard.config"},
                ]
            },
            {
                "category": "vmware_ws",
                "functions": [
                    {"name": "vmware.clipboard"},
                    {"name": "vmware.config"},
                    {"name": "vmware.draganddrop"},
                ]
            }
        ],
        "non_dissectable": [
            {
                "name": "mft",
                "category": "filesystems",
                "output": "warehouse/filesystems/mft.tsv",
                "commandline": ["ntfs_parser", "--mft-timeline", "01_target/C/$MFT", "{output}"],
                "duckdb_load_query": (
                    "CREATE OR REPLACE TABLE mft AS "
                    "SELECT Timestamp AS ts, "
                    "\"Timestamp Type\" AS ts_description, "
                    "Source AS record_type, "
                    "\"MFT reference number\" AS mft_ref_num,"
                    "\"Is in use\" AS is_inuse, "
                    "\"Is directory\" AS is_dir, "
                    "\"Log file sequence number\" AS LSN, "
                    "Path AS path,"
                    "\"$SI USN value\" AS USN, "
                    "\"File size\" AS size, "
                    "\"ADS list\" AS ADS"
                    " FROM read_csv_auto({output_sql}, header = true, "
                    "types = {'MFT reference number': 'VARCHAR', '$SI USN value': 'VARCHAR'})"
                ),
            },
            {
                "name": "usn",
                "category": "filesystems",
                "output": "warehouse/filesystems/usn.tsv",
                "commandline": ["ntfs_parser", "--usn", "01_target/C/$MFT", "01_target/C/$Extend/$J", "{output}"],
                "duckdb_load_query": (
                    "CREATE OR REPLACE TABLE usn AS "
                    "SELECT Timestamp AS ts,"
                    "Source AS source,"
                    "Reason AS reason,"
                    "\"MFT reference number\" AS mft_ref_num,"
                    "\"Parent MFT reference number\" AS parent_mft_ref_num,"
                    "\"File name\" AS filename,"
                    "\"File path (from $MFT)\" AS mft_filepath"
                    " FROM read_csv_auto({output_sql}, header = true, "
                    "types = {'MFT reference number': 'VARCHAR', 'Parent MFT reference number': 'VARCHAR'})"
                )
            },
        ],
    },
    "linux": {
        "dissectable": [
            {
                "category": "logs",
                "functions": [
                    {"name": "wtmp"},
                    {"name": "btmp"},
                    {"name": "utmp"},
                    {"name": "messages"},
                    {"name": "syslog"},
                    {"name", "lastlog"},
                    {"name", "journal"},
                    {"name", "securelog"},
                    {"name", "authlog"},
                    {"name", "audit"},
                    {"name", "atop"},
                ]
            },
            {
                "category": "packagemanager",
                "functions": [
                    {"name": "packagemanager.logs"}
                ]
            },
            {
                "category": "persistence",
                "functions": [
                    {"name": "services"},
                    {"name": "cronjobs"}
                ]
            },
            {
                "category": "firewall",
                "functions": [
                    {"name": "iptables"}
                ]
            },
            {
                "category": "execution",
                "functions": [
                    {"name": "bashhistory"},
                    {"name": "wget"},
                ]
            },
            {
                "category": "esxi",
                "functions": [
                    {"name": "vm.inventory"},
                    {"name": "vm.orphan"},
                ]
            },
            {
                "category": "vmware_ws",
                "functions": [
                    {"name": "vmware.clipboard"},
                    {"name": "vmware.config"},
                    {"name": "vmware.draganddrop"},
                ]
            },
            {
                "category": "browser",
                "functions": [
                    {"name": "browser.downloads"},
                    {"name": "browser.history"},
                    {"name": "browser.extensions"},
                    {"name": "browser.cookies"},
                    {"name": "browser.passwords"}
                ]
            },
            {
                "category": "webserver",
                "functions": [
                    {"name": "webserver.access"},
                    {"name": "webserver.error"},
                    {"name": "webserver.hosts"},
                ]
            },
            {
                "category": "ssh",
                "functions": [
                    {"name": "ssh.authroized_keys"},
                    {"name": "ssh.known_hosts"},
                    {"name": "opensshd.config"},
                    {"name": "putty.known_hosts"},
                    {"name": "putty.sessions"},
                ]
            },
            {
                "category": "vpn",
                "functions": [
                    {"name": "openvpn.config"},
                    {"name": "wireguard.config"},
                ]
            },
            {
                "category": "config",
                "functions": [
                    {"name": "passwords"},
                    {"name": "env"}
                ]
            }
        ],
        "non_dissectable": [
            {
                "name": "bodyfile",
                "category": "filesystems",
                "output": "warehouse/filesystems/bodyfile.csv",
                "commandline": ["mactime", "-b", "01_target/bodyfile/bodyfile.txt", "-z", "GMT", "-d", "-y", ">", "{output}"],
                "duckdb_load_query": (
                    "CREATE OR REPLACE TABLE bodyfile AS "
                    "SELECT Date AS ts, "
                    "Type AS ts_description, "
                    "Mode AS mode, "
                    "UID AS uid,"
                    "GID AS gid, "
                    "Meta as meta, "
                    "\"File Name\" AS path "
                    "FROM read_csv_auto({output_sql}, header = true)"
                ),
            },
        ]
    },
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
    pinned_columns: tuple[str, ...] | None
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
            name = _safe_name(function.get("name"))
            pinned_columns = function.get("pinned_columns")
            output = evidence / "warehouse" / category / f"{name}.jsonl"
            parsers.append(Parser(name, category, output, dissectable=True, pinned_columns=pinned_columns))

    for entry in profile.get("non_dissectable", []):
        name = _safe_name(entry["name"])
        category = _safe_name(entry.get("category", "main"))
        command = entry.get("commandline", "")
        if isinstance(command, str):
            command = shlex.split(command)
        if not isinstance(command, (list, tuple)) or any(not isinstance(arg, str) for arg in command):
            raise ValueError(f"{name}: commandline must be a string or a list of strings")
        output = evidence / entry["output"] if entry.get("output") else None
        query = entry.get("duckdb_load_query", "").strip()
        if output is None and ("{output}" in command or "{output_sql}" in query):
            raise ValueError(f"{name}: set output before using an output path placeholder")
        parsers.append(Parser(name, category, output, command=tuple(command), view_query=query, pinned_columns=None))

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
