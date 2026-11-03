"""
tasks.py - keeps track of scans and runs them in the background.

This file owns the `scans` dictionary (our temporary in-memory "database")
and everything that changes a scan's status:
    queued -> running -> completed (or failed)

The actual security checks live in scanner.py; this file just calls them.
"""

import asyncio
from uuid import uuid4

from scanner import scan_target

# Temporary storage for hackathon demonstration.
# Everything here is lost when the server restarts.
scans = {}


def register_scan(request):
    """Create a new scan entry with status "queued" and return its id.

    `request` is the ScanRequest model from schemas.py.
    """
    scan_id = str(uuid4())

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": str(request.target_url),
        "status": "queued",
        "results": None
    }

    return scan_id


def get_scan(scan_id):
    """Return one scan, or None if the id does not exist."""
    return scans.get(scan_id)


def list_scans():
    """Return every scan as a list."""
    return list(scans.values())


async def run_scan(scan_id, request):
    """Background job: run the scan and record the outcome."""
    scans[scan_id]["status"] = "running"

    try:
        # Simulate a scan job for demonstration.
        await asyncio.sleep(2)

        scans[scan_id]["results"] = scan_target(
            request.target_url,
            request.source_code,
            request.response_headers
        )

        scans[scan_id]["status"] = "completed"

    except Exception as error:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(error)
