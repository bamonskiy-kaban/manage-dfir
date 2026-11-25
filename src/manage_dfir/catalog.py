"""Register the parsed files as views in the Evidence's DuckDB catalog."""

import sys
from contextlib import chdir
from pathlib import Path

from .config import Parser


def _identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _dissect_view(connection, parser, view):
    path = parser.output.resolve().as_posix()
    schema = connection.execute(
        f"""DESCRIBE SELECT * FROM read_ndjson(
            {_literal(path)}, records = true, maximum_depth = 2,
            map_inference_threshold = -1, field_appearance_threshold = 0
        )"""
    ).fetchall()
    columns = {row[0]: row[1] for row in schema}
    ts = next((name for name in columns if name.lower() == "ts"), "ts")
    columns[ts] = "VARCHAR"
    column_types = ", ".join(f"{_identifier(name)}: {_literal(dtype)}" for name, dtype in columns.items())
    ts_expr = _identifier(ts)

    # ISO timestamps with explicit offsets represent instants. Offset-free
    # values keep their clock fields, independent of the client's TimeZone.
    connection.execute(f"""
        CREATE OR REPLACE VIEW {view} AS
        SELECT * EXCLUDE ({ts_expr}),
            CASE WHEN regexp_matches(substr({ts_expr}, 11), '[Zz+-]')
                THEN timezone('UTC', TRY_CAST({ts_expr} AS TIMESTAMPTZ))
                ELSE TRY_CAST({ts_expr} AS DATETIME)
            END AS ts
        FROM read_ndjson({_literal(path)}, columns = {{{column_types}}})
    """)


def _external_view(connection, parser):
    query = parser.view_query
    if "{output_sql}" in query:
        query = query.replace("{output_sql}", _literal(parser.output.resolve().as_posix()).replace('.', '_'))
    connection.execute(f"SET schema = {_literal(parser.category)}")
    try:
        connection.execute(query)
    finally:
        connection.execute("SET schema = 'main'")


def load(evidence: Path, parsers: list[Parser]) -> int:
    import duckdb

    database = evidence / "work" / "artifacts.duckdb"
    database.parent.mkdir(parents=True, exist_ok=True)
    failures = 0
    # Relative paths in custom SQL are resolved from the Evidence directory.
    with chdir(evidence), duckdb.connect(str(database)) as connection:
        for parser in parsers:
            if not (parser.dissectable or parser.view_query):
                continue
            schema = _identifier(parser.category)
            view = f"{schema}.{_identifier(parser.name).replace('.', '_')}"
            try:
                connection.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
                if parser.output is not None and (
                    not parser.output.is_file() or parser.output.stat().st_size == 0
                ):
                    # Remove the configured view if a previous load registered this source.
                    connection.execute(f"DROP VIEW IF EXISTS {view}")
                    print(f"[skip] {parser.category}.{parser.name} (source file is missing or empty)")
                    continue

                if parser.dissectable:
                    _dissect_view(connection, parser, view)
                else:
                    _external_view(connection, parser)
                print(f"[ok] {parser.category}.{parser.name}")
            except Exception as exc:
                failures += 1
                print(f"[error] {parser.category}.{parser.name}: {exc}", file=sys.stderr)
    print(database)
    return int(failures != 0)
