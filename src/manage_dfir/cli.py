"""Console entry points and dispatch."""

import argparse
import errno
import sys
from contextlib import chdir, contextmanager
from pathlib import Path


class EnvironmentBusy(Exception):
    pass


@contextmanager
def environment_lock(environment: Path):
    # Keep the lock file in place so competing invocations always open the same inode.
    path = environment / ".manage-dfir.lock"
    with path.open("a+b") as lock:
        if sys.platform == "win32":
            import msvcrt

            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                raise EnvironmentBusy from exc
        else:
            import fcntl

            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise EnvironmentBusy from exc
        yield


def main(argv: list[str] | None = None) -> int:
    from .config import get_parsers
    from .description import evidence_os, init_evidence
    from .parsing import parse_triage, run_sigma

    parser = argparse.ArgumentParser(prog="dfir", description="Process a local Evidence directory")
    parser.add_argument("--config", type=Path, help="PARSERS configuration file, relative to the Evidence root")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Collect host metadata")
    commands.add_parser("parse_triage", help="Run the parsers configured for the host OS")
    commands.add_parser("sigma", help="Run Hayabusa on Windows evidence")
    commands.add_parser("load", help="Create DuckDB tables")
    args = parser.parse_args(argv)

    try:
        if sys.prefix == sys.base_prefix:
            raise ValueError("Run dfir from a virtual environment created inside the Evidence directory")
        environment = Path(sys.prefix)
        evidence = environment.parent.resolve()
        with environment_lock(environment), chdir(evidence):
            if args.command == "init":
                init_evidence(evidence)
                return 0
            os_name = evidence_os(evidence)
            if args.command == "sigma":
                if os_name != "windows":
                    raise ValueError(f"sigma requires Windows evidence. Detected OS: {os_name!r}")
                run_sigma(evidence)
                return 0
            config = (evidence / args.config).resolve(strict=True) if args.config else None
            parsers = get_parsers(evidence, os_name, config)
            if args.command == "parse_triage":
                return parse_triage(evidence, parsers)

            from .catalog import load

            return load(evidence, parsers)
    except EnvironmentBusy:
        print("dfir: another dfir command is running in this virtual environment", file=sys.stderr)
        return 75
    except KeyboardInterrupt:
        print("dfir: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"dfir: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
