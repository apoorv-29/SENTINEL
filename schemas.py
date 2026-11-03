"""
schemas.py - the "shape" of the data going in and out of the API.

Pydantic models do two jobs for us:
  1. Validate incoming requests (e.g. reject a bad URL automatically).
  2. Describe our responses, so FastAPI's /docs page shows them clearly.

The field names and order here match the JSON the API already returned,
so your frontend teammate's code keeps working unchanged.
"""

from typing import Optional
from pydantic import BaseModel, HttpUrl


# ---------- Request ----------

class ScanRequest(BaseModel):
    target_url: HttpUrl
    authorized: bool
    source_code: Optional[str] = None
    response_headers: Optional[dict[str, str]] = None


# ---------- Simple responses ----------

class HomeResponse(BaseModel):
    message: str
    status: str


class ScanCreatedResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str


# ---------- Scan results (nested pieces first, then the whole thing) ----------

class Finding(BaseModel):
    title: str
    severity: str
    category: str
    description: str


class GraphNode(BaseModel):
    id: str
    label: str
    severity: str
    # The central "target" node has no category, so this stays optional.
    category: Optional[str] = None


class GraphEdge(BaseModel):
    source: str
    target: str


class Graph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class ScanResults(BaseModel):
    total_findings: int
    findings: list[Finding]
    graph: Graph


# ---------- Responses that depend on the scan's state ----------

class PendingResultsResponse(BaseModel):
    """Returned by /scans/{id}/results while a scan is not finished yet."""
    scan_id: str
    status: str
    results: Optional[ScanResults] = None


class ScanRecord(BaseModel):
    """One scan as listed by GET /scans."""
    scan_id: str
    target: str
    status: str
    results: Optional[ScanResults] = None
    # Only present if the scan failed.
    error: Optional[str] = None
