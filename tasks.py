"""Scan orchestration for the Phase 1 service boundary."""

import asyncio
import json
from uuid import uuid4

from scanner import scan_target
from storage import create_scan, get_scan as storage_get_scan, list_scans as storage_list_scans, update_scan


def register_scan(request, user: dict) -> str:
    scan_id = str(uuid4())
    payload = request.model_dump(mode="json")
    create_scan(scan_id, user["id"], user["organization_id"], str(request.target_url), json.dumps(payload))
    return scan_id


def get_scan(scan_id: str, user: dict):
    return storage_get_scan(scan_id, user)


def list_scans(user: dict):
    rows = storage_list_scans(user)
    output = []
    for row in rows:
        item = {"scan_id": row["id"], "target": row["target"], "status": row["status"]}
        if row["results_json"]:
            item["results"] = json.loads(row["results_json"])
        if row["error_code"]:
            item["error"] = row["error_code"]
        output.append(item)
    return output


async def run_scan(scan_id: str, request) -> None:
    update_scan(scan_id, status="running")
    try:
        await asyncio.sleep(0.05)
        results = scan_target(request.target_url, request.source_code, request.response_headers)
        update_scan(scan_id, status="completed", results_json=json.dumps(results), error_code=None)
    except Exception:
        # Do not persist exception messages: they can contain URLs, source, or credentials.
        update_scan(scan_id, status="failed", error_code="scan_execution_failed")
