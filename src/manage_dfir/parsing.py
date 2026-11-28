"""Run native and external parsers and publish their outputs and logs."""

import csv
import json
import logging
import multiprocessing
import os
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout, suppress
from dataclasses import asdict, dataclass, fields
from functools import lru_cache
from pathlib import Path

from .config import EXCLUDE_KEYS, Parser


@contextmanager
def staged_file(output: Path):
    output.parent.mkdir(parents=True, exist_ok=True)
    # Keep the real file extension for tools that use it to choose an output format.
    with tempfile.TemporaryDirectory(prefix=".dfir-", dir=output.parent) as directory:
        yield Path(directory) / output.name


def _venv_command(name: str) -> str:
    scripts = "Scripts" if sys.platform == "win32" else "bin"
    executable = f"{name}.exe" if sys.platform == "win32" and not name.lower().endswith(".exe") else name
    local = Path(sys.prefix) / scripts / executable
    return str(local) if local.is_file() else name


class ProcessRunner:
    def __init__(self, evidence: Path):
        self.evidence = evidence
        self._lock = threading.Lock()
        self._running = set()
        self._cancelled = False

    @contextmanager
    def start(self, args, **redirects):
        with self._lock:
            if self._cancelled:
                raise RuntimeError("Parsing interrupted")
            args = (_venv_command(args[0]), *args[1:]) if not Path(args[0]).is_absolute() else args
            process = subprocess.Popen(args, cwd=self.evidence, **redirects)
            self._running.add(process)
        try:
            yield process
        finally:
            with self._lock:
                if process.poll() is None:
                    with suppress(ProcessLookupError):
                        process.kill()
            process.wait()
            with self._lock:
                self._running.discard(process)

    def cancel(self):
        with self._lock:
            self._cancelled = True
            for process in self._running:
                if process.poll() is None:
                    with suppress(ProcessLookupError):
                        process.kill()


@dataclass
class Outcome:
    parser: str
    category: str
    kind: str
    status: str = "ok"
    seconds: float = 0
    exit_codes: str = ""
    output: str = ""
    log: str = ""
    detail: str = ""


_worker_stop = None


def _init_dissect_worker(stop):
    global _worker_stop
    _worker_stop = stop


@lru_cache(maxsize=1)
def _open_target(path: Path):
    from dissect.target import Target

    return Target.open(path)


def _run_dissect(name, evidence, output, log):
    from dissect.target.exceptions import UnsupportedPluginError
    from flow.record import JsonRecordPacker, iter_timestamped_records

    if _worker_stop is not None and _worker_stop.is_set():
        raise InterruptedError("Parsing interrupted")

    handler = logging.StreamHandler(log)
    handler.setLevel(logging.WARNING)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    try:
        with redirect_stdout(log), redirect_stderr(log):
            target = _open_target(evidence / "01_target")
            function = target
            try:
                for part in name.split("."):
                    function = getattr(function, part)
            except UnsupportedPluginError as exc:
                print(f"{name}: {exc}", file=log)
                return
            if not callable(function):
                raise TypeError(f"Dissect function {name!r} is not callable")

            packer = JsonRecordPacker(pack_descriptors=False)
            encode = json.JSONEncoder(default=packer.pack_obj).encode
            for index, record in enumerate(function()):
                if index % 1024 == 0 and _worker_stop is not None and _worker_stop.is_set():
                    raise InterruptedError("Parsing interrupted")
                for event in iter_timestamped_records(record):
                    payload = packer.pack_obj(event)
                    for key in EXCLUDE_KEYS:
                        payload.pop(key, None)
                    if not payload.get("ts"):
                        payload["ts"] = "1970-01-01T00:00:00.000000"
                    output.write(encode(payload) + "\n")
    finally:
        root_logger.removeHandler(handler)
        handler.close()


def _run_external(command, runner, log, output):
    if "/" in command[0] or os.sep in command[0]:
        command = (str((runner.evidence / command[0]).resolve()), *command[1:])
    with runner.start(command, stdin=subprocess.DEVNULL, stdout=output if output else log, stderr=log) as process:
        return {Path(command[0]).name: process.wait()}


def _publish_output(staging, output):
    if not staging.is_file():
        raise ValueError(f"Parser did not produce the expected output file {output}")
    staging.replace(output)


def _outcome(parser, evidence):
    kind = "dissectable" if parser.dissectable else "non_dissectable"
    outcome = Outcome(parser.name, parser.category, kind)
    output = parser.output
    if output is not None:
        outcome.output = str(output.relative_to(evidence)) if output.is_relative_to(evidence) else str(output)
    return outcome


def _run_parser(parser, evidence, log_dir, runner=None):
    started = time.monotonic()
    output = parser.output
    log_path = log_dir / f"{parser.name}.log"
    outcome = _outcome(parser, evidence)

    with log_path.open("w", encoding="utf-8", errors="backslashreplace") as log, ExitStack() as stack:
        try:
            if parser.dissectable or "{output}" in parser.command:
                staging = stack.enter_context(staged_file(output))
            else:
                staging = output
                if output is not None:
                    output.parent.mkdir(parents=True, exist_ok=True)

            if parser.dissectable:
                with staging.open("w", encoding="utf-8", newline="\n") as stream:
                    _run_dissect(parser.name, evidence, stream, log)
                if _worker_stop is not None and _worker_stop.is_set():
                    raise InterruptedError("Parsing interrupted")
                codes = {}
            else:
                command = [str(staging) if arg == "{output}" else arg for arg in parser.command]
                output = parser.get("output") if parser.get("redirect") else None
                codes = _run_external(command, runner, log, output)

            outcome.exit_codes = " ".join(f"{program}={code}" for program, code in codes.items())
            if any(code != 0 for code in codes.values()):
                outcome.status = "error"
                outcome.detail = f"Parser exited with a nonzero status ({outcome.exit_codes})"
            elif output is not None:
                if staging != output:
                    _publish_output(staging, output)
                if not output.is_file():
                    raise ValueError(f"Parser did not produce the expected output file {output}")
                if output.stat().st_size == 0:
                    outcome.status = "empty"
                    outcome.detail = "Parser produced an empty file"
        except Exception as exc:
            outcome.status = "error"
            outcome.detail = str(exc)
            traceback.print_exc(file=log)

    log_size = log_path.stat().st_size
    if log_size:
        outcome.log = str(log_path.relative_to(evidence))
        if outcome.status == "ok" and parser.dissectable:
            outcome.status = "diagnostics"
            outcome.detail = "Dissect logged diagnostic messages"
        if outcome.status != "ok":
            with log_path.open("rb") as log:
                log.seek(max(0, log_size - 4096))
                tail = log.read().decode("utf-8", errors="replace").strip().splitlines()
            if tail:
                outcome.detail = f"{outcome.detail} | {tail[-1][:500]}"
    else:
        log_path.unlink()
    outcome.seconds = round(time.monotonic() - started, 3)
    return outcome


def parse_triage(evidence: Path, parsers: list[Parser]) -> int:
    try:
        jobs = int(os.environ.get("DFIR_PROCESSES", "16"))
        if jobs < 1:
            raise ValueError
    except ValueError as exc:
        raise ValueError("DFIR_PROCESSES must be a positive integer") from exc

    if not (evidence / "01_target").is_dir():
        raise ValueError(f"Evidence data directory not found at {evidence / '01_target'}")
    log_dir = evidence / "99_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    runner = ProcessRunner(evidence)
    selected = [parser for parser in parsers if parser.dissectable or parser.command]
    native_count = sum(parser.dissectable for parser in selected)
    external_count = len(selected) - native_count
    outcomes = {}

    def record(outcome):
        outcomes[outcome.parser] = outcome
        print(f"[{outcome.status}] {outcome.parser}", flush=True)

    def failed(parser, exc):
        outcome = _outcome(parser, evidence)
        outcome.status = "error"
        outcome.detail = str(exc)
        log_path = log_dir / f"{parser.name}.log"
        if log_path.is_file() and log_path.stat().st_size:
            outcome.log = str(log_path.relative_to(evidence))
        record(outcome)

    with ExitStack() as stack:
        stop = None
        if native_count:
            context = multiprocessing.get_context("spawn")
            stop = context.Event()
            native = stack.enter_context(ProcessPoolExecutor(
                max_workers=min(jobs, native_count),
                mp_context=context,
                initializer=_init_dissect_worker,
                initargs=(stop,),
                max_tasks_per_child=1,
            ))
        if external_count:
            external = stack.enter_context(ThreadPoolExecutor(max_workers=min(jobs, external_count)))

        pending = iter(selected)
        active = {}
        try:
            while True:
                while len(active) < jobs and (parser := next(pending, None)) is not None:
                    try:
                        if parser.dissectable:
                            future = native.submit(_run_parser, parser, evidence, log_dir)
                        else:
                            future = external.submit(_run_parser, parser, evidence, log_dir, runner)
                    except BrokenProcessPool as exc:
                        failed(parser, exc)
                    else:
                        active[future] = parser
                if not active:
                    break

                done, _ = wait(active, return_when=FIRST_COMPLETED)
                for future in done:
                    parser = active.pop(future)
                    try:
                        record(future.result())
                    except Exception as exc:
                        failed(parser, exc)
        except BaseException:
            if stop is not None:
                stop.set()
            runner.cancel()
            for future in active:
                future.cancel()
            raise

    summary = log_dir / "00_parsing_log.csv"
    with staged_file(summary) as staging:
        with staging.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=[field.name for field in fields(Outcome)])
            writer.writeheader()
            writer.writerows(asdict(outcomes[parser.name]) for parser in selected)
        staging.replace(summary)
    print(summary)
    return int(any(outcome.status == "error" for outcome in outcomes.values()))


def run_sigma(evidence: Path) -> None:
    if not (evidence / "01_target").is_dir():
        raise ValueError(f"Evidence data directory not found at {evidence / '01_target'}")
    binary = os.environ.get("DFIR_HAYABUSA", "hayabusa")
    output = evidence / "work" / "hayabusa.csv"
    log_path = evidence / "99_logs" / "hayabusa.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    runner = ProcessRunner(evidence)
    with log_path.open("wb") as log, staged_file(output) as staging:
        command = (
            binary, "dfir-timeline", "--directory", "01_target", "-o", str(staging),
            "-O", "-U", "-w", "-Q", "-q",
        )
        try:
            codes = _run_external(command, runner, log)
            code = next(iter(codes.values()))
            if code != 0:
                raise RuntimeError(f"Hayabusa exited with code {code}")
            _publish_output(staging, output)
        except Exception as exc:
            log.write(traceback.format_exc().encode("utf-8", errors="backslashreplace"))
            raise RuntimeError(f"{exc}. See {log_path} for details.") from exc
    if log_path.stat().st_size == 0:
        log_path.unlink()
    print(output)
