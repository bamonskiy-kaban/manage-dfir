"""Collect host metadata from Dissect and read it back for dispatch."""

import json
import traceback
from pathlib import Path

from .config import EXCLUDE_KEYS
from .parsing import staged_file


def init_evidence(evidence: Path) -> None:
    from dissect.target.target import Target
    from flow.record import JsonRecordPacker

    target_path = evidence / "01_target"
    if not target_path.is_dir():
        raise ValueError(f"Evidence data directory not found at {target_path}")
    output = evidence / "description.jsonl"
    log_path = evidence / "99_logs" / "description.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    packer = JsonRecordPacker()

    with log_path.open("w", encoding="utf-8") as log:
        try:
            target = Target.open(target_path)
            os_name = target.os
            if not isinstance(os_name, str) or not os_name.strip():
                raise ValueError("Dissect could not determine the operating system")

            def optional(label, collect, fallback):
                try:
                    return collect()
                except Exception:
                    print(f"[{label}]", file=log)
                    traceback.print_exc(file=log)
                    return fallback

            def records(generator):
                result = []
                for record in generator():
                    packed = packer.pack_obj(record)
                    result.append({key: value for key, value in packed.items() if key not in EXCLUDE_KEYS})
                return result

            base = {"os": os_name}
            fields = {
                "hostname": "hostname", "domain": "domain", "arch": "architecture",
                "version": "version", "timezone": "timezone", "ips": "ips", "language": "language",
            }
            for name, attribute in fields.items():
                base[name] = optional(name, lambda attribute=attribute: getattr(target, attribute), None)
            description = {
                "base": base,
                "sid": optional("sid", lambda: records(target.sid), []),
                "users": optional("users", lambda: records(target.users), []),
                "interfaces": optional("interfaces", lambda: records(target.network.interfaces), []),
            }

            with staged_file(output) as staging:
                with staging.open("w", encoding="utf-8", newline="\n") as stream:
                    json.dump(description, stream, default=packer.pack_obj, ensure_ascii=False)
                    stream.write("\n")
                staging.replace(output)
        except Exception:
            traceback.print_exc(file=log)
            raise
    if log_path.stat().st_size == 0:
        log_path.unlink()
    else:
        print(f"See {log_path} for details on unavailable metadata fields")
    print(output)


def evidence_os(evidence: Path) -> str:
    path = evidence / "description.jsonl"
    if not path.is_file():
        raise ValueError(f"{path} is missing. Run dfir init first.")
    with path.open(encoding="utf-8") as stream:
        description = json.load(stream)
    base = description.get("base") if isinstance(description, dict) else None
    os_name = base.get("os") if isinstance(base, dict) else None
    if not isinstance(os_name, str) or not os_name.strip():
        raise ValueError(f"{path} must contain a non-empty string in base.os")
    return os_name.strip().lower()
