"""
Shared pytest fixtures.

Every test run builds a FRESH temporary database from a small synthetic dataset,
so tests never touch data/threat_intel.db and never need the network.
"""
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import create_app  # noqa: E402
from backend.database import get_connection  # noqa: E402
from backend.init_db import config_dict, init_database  # noqa: E402
from data.generate_threat_data import (  # noqa: E402
    THREAT_FIELDS,
    VULN_FIELDS,
    generate_threat_records,
    generate_vulnerabilities,
    write_csv,
)

REF_DATE = date(2026, 9, 29)
YEAR = REF_DATE.year
DEMO_ID = f"THR-{YEAR}-001"
ANALYST = {"X-API-Key": "test-analyst-key"}
ADMIN = {"X-API-Key": "test-admin-key"}


@pytest.fixture(scope="session")
def dataset_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("dataset")
    vulns = generate_vulnerabilities(20, 42, REF_DATE)
    threats = generate_threat_records(200, 42, REF_DATE, cve_ids=[v["cve_id"] for v in vulns[2:]])
    write_csv(d / "threat_intelligence_dataset.csv", threats, THREAT_FIELDS)
    write_csv(d / "vulnerabilities.csv", vulns, VULN_FIELDS)
    # An empty feed (header only) for the empty-dataset test.
    write_csv(d / "empty_threats.csv", [], THREAT_FIELDS)
    write_csv(d / "empty_vulns.csv", [], VULN_FIELDS)
    return d


def _config(tmp_path, dataset_dir, empty=False):
    cfg = config_dict()
    cfg.update(
        TESTING=True,
        DATABASE_PATH=str(tmp_path / "test.db"),
        THREAT_CSV=str(dataset_dir / ("empty_threats.csv" if empty else "threat_intelligence_dataset.csv")),
        VULN_CSV=str(dataset_dir / ("empty_vulns.csv" if empty else "vulnerabilities.csv")),
        ANALYST_API_KEY=ANALYST["X-API-Key"],
        ADMIN_API_KEY=ADMIN["X-API-Key"],
        RATE_LIMIT_PER_MINUTE=0,  # disabled in tests
    )
    return cfg


@pytest.fixture
def app(tmp_path, dataset_dir):
    cfg = _config(tmp_path, dataset_dir)
    init_database(cfg)
    return create_app(cfg)


@pytest.fixture
def empty_app(tmp_path, dataset_dir):
    cfg = _config(tmp_path, dataset_dir, empty=True)
    init_database(cfg, seed_quiz_history=False)
    return create_app(cfg)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    conn = get_connection(app.config["DATABASE_PATH"])
    yield conn
    conn.close()
