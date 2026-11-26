"""Register the parsed files as views in the Evidence's DuckDB catalog."""

import sys
from contextlib import chdir
from pathlib import Path

from .config import Parser
from .utils import identifier, literal


def _dissect_view(connection, parser, view):
    path = parser.output.resolve().as_posix()
    schema = connection.execute(
        f"""DESCRIBE SELECT * FROM read_ndjson(
            {literal(path)}, records = true, maximum_depth = 2,
            map_inference_threshold = -1, field_appearance_threshold = 0, sample_size = -1
        )"""
    ).fetchall()
    columns = {row[0]: row[1] for row in schema}
    column_types = ", ".join(f"{identifier(name)}: {literal("VARCHAR")}" for name, dtype in columns.items())

    connection.execute(f"""
        CREATE OR REPLACE VIEW {view} AS
        SELECT CASE WHEN regexp_matches(substr(ts, 11), '[Zz+-]')
                THEN timezone('UTC', TRY_CAST(ts AS TIMESTAMPTZ))
                ELSE TRY_CAST(ts AS DATETIME)
            END AS "ts", * EXCLUDE(ts)
        FROM read_ndjson({literal(path)}, columns = {{{column_types}}})
    """)



def _dissect_compact_view(connection, parser, view):
    path = parser.output.resolve().as_posix()
    columns = ["ts_description", *parser.pinned_columns]

    excluded = ", ".join(
        literal(name) for name in ["ts", *columns]
    )

    select_columns = [
        """
        CASE
            WHEN regexp_matches(substr(raw_ts, 11), '[Zz+-]')
            THEN timezone('UTC', TRY_CAST(raw_ts AS TIMESTAMPTZ))
            ELSE TRY_CAST(raw_ts AS TIMESTAMP)
        END AS ts
        """
    ]

    select_columns.extend(
        f"json_extract_string(doc, {literal(name)}) AS {identifier(name)}"
        for name in columns
    )

    select_columns.append(
        f"""
        to_json(
            map_from_entries(
                list_filter(
                    map_entries(CAST(doc AS MAP(VARCHAR, JSON))),
                    lambda x: x.key NOT IN ({excluded})
                )
            )
        ) AS extra
        """
    )

    projection = ",\n".join(select_columns)

    connection.execute(
        f"""
        CREATE OR REPLACE VIEW {view} AS
        WITH source AS (
            SELECT
                json AS doc,
                json_extract_string(json, 'ts') AS raw_ts
            FROM read_ndjson_objects({literal(path)})
        )
        SELECT
            {projection}
        FROM source
        """
    )

def _external_view(connection, parser):
    query = parser.view_query
    if "{output_sql}" in query:
        query = query.replace("{output_sql}", literal(parser.output.resolve().as_posix()))
    connection.execute(query)


def load(evidence: Path, parsers: list[Parser]) -> int:
    import duckdb

    database = evidence / "work" / "data.duckdb"
    database.parent.mkdir(parents=True, exist_ok=True)
    failures = 0
    # Relative paths in custom SQL are resolved from the Evidence directory.
    with chdir(evidence), duckdb.connect(str(database)) as connection:
        for parser in parsers:
            if not (parser.dissectable or parser.view_query):
                continue
            view = f"{identifier(parser.name).replace('.', '_')}"
            try:
                if parser.output is not None and (
                    not parser.output.is_file() or parser.output.stat().st_size == 0
                ):
                    # Remove the configured view if a previous load registered this source.
                    connection.execute(f"DROP VIEW IF EXISTS {view}")
                    print(f"[skip] {parser.category}.{parser.name} (source file is missing or empty)")
                    continue

                if parser.dissectable:
                    if not parser.pinned_columns:
                        _dissect_view(connection, parser, view)
                    else:
                        _dissect_compact_view(connection, parser, view)
                else:
                    _external_view(connection, parser)
                print(f"[ok] {parser.category}.{parser.name}")
            except Exception as exc:
                failures += 1
                print(f"[error] {parser.category}.{parser.name}: {exc}", file=sys.stderr)
    print(database)
    return int(failures != 0)
