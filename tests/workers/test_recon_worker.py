import json
from datetime import datetime, timezone

import pytest

from workers.recon.worker import ReconJob, ReconWorker, WorkerConfig, normalize_asset


def test_normalize_asset_handles_common_types():
    asset_type, normalized = normalize_asset("Example.COM")
    assert asset_type == "domain"
    assert normalized == "example.com"

    asset_type, normalized = normalize_asset("2001:db8::1")
    assert asset_type == "ipv6"
    assert normalized == "2001:db8::1"

    asset_type, normalized = normalize_asset("https://App.example.com/Login")
    assert asset_type == "url"
    assert normalized == "https://app.example.com/login"

    with pytest.raises(ValueError):
        normalize_asset("")

    with pytest.raises(ValueError):
        normalize_asset("ftp://")


def test_collect_assets_from_csv(tmp_path):
    csv_path = tmp_path / "inventory.csv"
    csv_path.write_text(
        "asset,asset_type\n"
        "app.example.com,domain\n"
        "app.example.com,domain\n"
        "vpn.evil.com,domain\n"
        "10.0.0.5,ipv4\n",
        encoding="utf-8",
    )

    job_payload = {
        "job_id": "job-1",
        "source": "inventory:web",
        "callback_url": "https://controller.local/internal/recon",
        "feed": {
            "type": "csv",
            "url": f"file://{csv_path}",
            "asset_column": "asset",
            "asset_type_column": "asset_type",
        },
        "authorized_scopes": ["example.com", "10.0.0.0/24"],
        "labels": ["inventory"],
    }

    job = ReconJob.from_json(json.dumps(job_payload))
    worker = ReconWorker(WorkerConfig(), redis_client=None, http_session=None)

    assets = worker.collect_assets(job)
    assert len(assets) == 2

    domain_asset = next(asset for asset in assets if asset.asset_type == "domain")
    assert domain_asset.normalized_value == "app.example.com"
    assert domain_asset.occurrences == 2
    assert domain_asset.matched_scope == "example.com"
    assert domain_asset.metadata.get("labels") == ["inventory"]

    ip_asset = next(asset for asset in assets if asset.asset_type == "ipv4")
    assert ip_asset.normalized_value == "10.0.0.5"
    assert ip_asset.matched_scope == "10.0.0.0/24"


def test_collect_assets_from_api(tmp_path):
    json_path = tmp_path / "inventory.json"
    json_path.write_text(
        json.dumps(
            {
                "results": [
                    {"asset": "vpn.example.com", "type": "domain"},
                    {"asset": "api.example.com", "type": "domain"},
                    {"asset": "11.0.0.5", "type": "ipv4"},
                ]
            }
        ),
        encoding="utf-8",
    )

    job_payload = {
        "job_id": "job-2",
        "source": "inventory:api",
        "callback_url": "https://controller.local/internal/recon",
        "feed": {
            "type": "api",
            "url": f"file://{json_path}",
            "items_path": ["results"],
            "asset_field": "asset",
            "type_field": "type",
        },
        "authorized_scopes": ["example.com"],
        "labels": [],
    }

    job = ReconJob.from_json(json.dumps(job_payload))
    worker = ReconWorker(WorkerConfig(), redis_client=None, http_session=None)

    assets = worker.collect_assets(job)
    assert len(assets) == 2
    hosts = {asset.normalized_value for asset in assets}
    assert "vpn.example.com" in hosts
    assert "api.example.com" in hosts
    for asset in assets:
        assert asset.matched_scope == "example.com"
