"""
main.py - the FastAPI app and its API routes.

Routes stay thin on purpose: they check the request, call a function from
tasks.py or scanner.py, and return the result.

Run it with:  uvicorn main:app --reload
"""

from typing import Union

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import tasks
from schemas import (
    ScanRequest,
    HomeResponse,
    ScanCreatedResponse,
    ScanStatusResponse,
    ScanResults,
    PendingResultsResponse,
    ScanRecord,
)

app = FastAPI(
    title="Sentinel Security Scanner",
    description="Zero-Trust API Security Dashboard",
    version="1.0.0"
)

# Allow your frontend to communicate with the backend.
# Restrict this to your frontend origin before deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=HomeResponse)
async def home():
    return {
        "message": "Sentinel Security API is running!",
        "status": "online"
    }


@app.post("/scans", response_model=ScanCreatedResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    if not request.authorized:
        raise HTTPException(
            status_code=403,
            detail="Please confirm you are authorized to analyze this target."
        )

    scan_id = tasks.register_scan(request)

    background_tasks.add_task(
        tasks.run_scan,
        scan_id,
        request
    )

    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Scan successfully created!"
    }


# response_model_exclude_unset=True means "only send the fields we actually
# set". It keeps the JSON identical to before (for example, the "error" field
# only appears on failed scans).
@app.get("/scans", response_model=list[ScanRecord], response_model_exclude_unset=True)
async def get_scans():
    return tasks.list_scans()


@app.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    scan = tasks.get_scan(scan_id)

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "status": scan["status"]
    }


@app.get(
    "/scans/{scan_id}/results",
    response_model=Union[ScanResults, PendingResultsResponse],
    response_model_exclude_unset=True
)
async def get_scan_results(scan_id: str):
    scan = tasks.get_scan(scan_id)

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["status"] != "completed":
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "results": None
        }

    return scan["results"]
