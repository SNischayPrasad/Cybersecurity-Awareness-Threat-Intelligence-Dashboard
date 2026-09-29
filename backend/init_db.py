"""
Initialise (or rebuild) the SQLite database from the synthetic CSV files.

Usage (from the project root):
    python -m backend.init_db              # rebuild database from existing CSVs
    python -m backend.init_db --generate   # regenerate synthetic CSVs first
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.config import Config  # noqa: E402
from backend.database import create_schema, drop_all, get_connection  # noqa: E402
from backend.services.ingestion import run_full_pipeline  # noqa: E402


def config_dict(cfg=Config) -> dict:
    return {k: getattr(cfg, k) for k in dir(cfg) if k.isupper()}


def init_database(config: dict | None = None, generate: bool = False, seed_quiz_history: bool = True) -> dict:
    config = config or config_dict()
    if generate or not Path(config["THREAT_CSV"]).exists():
        from data.generate_threat_data import main as generate_main

        generate_main(["--out-dir", str(Path(config["THREAT_CSV"]).parent)])
    conn = get_connection(config["DATABASE_PATH"])
    try:
        drop_all(conn)
        create_schema(conn)
        return run_full_pipeline(conn, config, seed_quiz_history)
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the threat-intel SQLite database.")
    parser.add_argument("--generate", action="store_true", help="regenerate the synthetic CSVs first")
    args = parser.parse_args(argv)
    report = init_database(generate=args.generate)
    print("[+] Database initialised:", Config.DATABASE_PATH)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
