"""SENTINEL API entrypoint.

Phase 1 establishes the service boundary. PostgreSQL and durable workers are
intentionally deferred to Phase 2; this module already keeps authorization
checks at the API/service boundary so the storage implementation can change.
"""

import os
from pathlib import Path
from typing import Union

import tasks
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from schemas import (
    HomeResponse, LoginRequest, PendingResultsResponse, RefreshRequest,
    RegisterRequest, ScanCreatedResponse, ScanRecord, ScanRequest,
    ScanResults, ScanStatusResponse, TokenResponse, UserResponse,
)
from storage import (
    authenticate, create_message, find_users, init_db, list_messages, register_user,
    revoke_token, rotate_refresh_token, search_scan_rows, user_exists, user_from_token,
)

init_db()
app = FastAPI(title="Sentinel Security Scanner", description="Zero-Trust API Security Dashboard", version="1.1.0")

origins = [origin.strip() for origin in os.getenv("SENTINEL_CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 1_000_000:
        return JSONResponse(status_code=413, content={"detail": "request body too large"})
    return await call_next(request)


bearer = HTTPBearer(auto_error=False)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="authentication required", headers={"WWW-Authenticate": "Bearer"})
    user = user_from_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="invalid or expired access token", headers={"WWW-Authenticate": "Bearer"})
    return user


def _tokens(user: dict, access: str, refresh: str) -> dict:
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer", "user": user}


def _record(row: dict) -> dict:
    result = {"scan_id": row["id"], "status": row["status"]}
    if row.get("results_json"):
        import json
        result["results"] = json.loads(row["results_json"])
    return result


PROJECT_ROOT = Path(__file__).resolve().parent


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(PROJECT_ROOT / "SENTINEL Dashboard.html", media_type="text/html")


@app.get("/health", response_model=HomeResponse, include_in_schema=False)
async def health():
    return {"message": "Sentinel Security API is running!", "status": "online"}


@app.get("/api/v1/health", response_model=HomeResponse)
async def api_health():
    return {"message": "Sentinel Security API is running!", "status": "online"}


@app.get("/manus-routes.json", include_in_schema=False)
async def route_manifest():
    return FileResponse(PROJECT_ROOT / "public" / "manus-routes.json", media_type="application/json")


@app.post("/api/v1/auth/register", response_model=TokenResponse, status_code=201)
async def register(request: RegisterRequest):
    try:
        user, access, refresh = register_user(request.email, request.password, request.organization_name)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _tokens(user, access, refresh)


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    result = authenticate(request.email, request.password)
    if not result:
        raise HTTPException(status_code=401, detail="invalid credentials")
    user, access, refresh = result
    return _tokens(user, access, refresh)


@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest):
    result = rotate_refresh_token(request.refresh_token)
    if not result:
        raise HTTPException(status_code=401, detail="invalid or expired refresh token")
    user, access, refresh_token = result
    return _tokens(user, access, refresh_token)


@app.post("/api/v1/auth/logout", status_code=204)
async def logout(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if credentials and credentials.scheme.lower() == "bearer":
        revoke_token(credentials.credentials)


@app.get("/api/v1/auth/me", response_model=UserResponse)
async def me(user: dict = Depends(current_user)):
    return user


@app.get("/api/v1/search")
async def search(q: str = "", severity: str = "", category: str = "", status: str = "", user: dict = Depends(current_user)):
    allowed_severities = {"", "low", "medium", "high", "critical"}
    if severity not in allowed_severities:
        raise HTTPException(status_code=400, detail="invalid severity filter")
    return {"query": q, "filters": {"severity": severity, "category": category, "status": status}, "results": search_scan_rows(user, q, severity, category, status)}


@app.get("/api/v1/automation/scan-summary")
async def automated_scan_summary(user: dict = Depends(current_user)):
    """Automate the manual work of reviewing every scan individually."""
    rows = search_scan_rows(user)
    findings = [finding for row in rows for finding in row["findings"]]
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
    return {"scan_count": len(rows), "finding_count": len(findings), "by_severity": by_severity, "by_category": by_category, "recent_scans": rows[:10]}


@app.get("/api/v1/chat/users")
async def chat_users(q: str = "", user: dict = Depends(current_user)):
    return {"users": find_users(q, user["id"])}


@app.get("/api/v1/chat/{other_user_id}/messages")
async def chat_history(other_user_id: str, user: dict = Depends(current_user)):
    if not user_exists(other_user_id):
        raise HTTPException(status_code=404, detail="user not found")
    return {"messages": list_messages(user["id"], other_user_id)}


@app.post("/api/v1/chat/{other_user_id}/messages")
async def send_chat_message(other_user_id: str, payload: dict, user: dict = Depends(current_user)):
    body = payload.get("body") if isinstance(payload, dict) else None
    if not isinstance(body, str) or not body.strip() or len(body) > 4000:
        raise HTTPException(status_code=422, detail="message body must be 1-4000 characters")
    if not user_exists(other_user_id):
        raise HTTPException(status_code=404, detail="user not found")
    message = create_message(user["id"], other_user_id, body.strip())
    await _broadcast(other_user_id, message)
    await _broadcast(user["id"], message)
    return message


active_chat_sockets: dict[str, set[WebSocket]] = {}


async def _broadcast(user_id: str, message: dict) -> None:
    stale = []
    for socket in active_chat_sockets.get(user_id, set()):
        try:
            await socket.send_json(message)
        except Exception:
            stale.append(socket)
    for socket in stale:
        active_chat_sockets.get(user_id, set()).discard(socket)


@app.websocket("/api/v1/chat/ws/{user_id}")
async def chat_websocket(websocket: WebSocket, user_id: str, token: str = ""):
    authenticated = user_from_token(token) if token else None
    if not authenticated or authenticated["id"] != user_id:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    active_chat_sockets.setdefault(user_id, set()).add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        active_chat_sockets.get(user_id, set()).discard(websocket)


async def create_scan(request: ScanRequest, user: dict = Depends(current_user), background_tasks=None):
    scan_id = tasks.register_scan(request, user)
    if background_tasks is not None:
        background_tasks.add_task(tasks.run_scan, scan_id, request)
    return {"scan_id": scan_id, "status": "queued", "message": "Scan successfully created!"}


@app.post("/api/v1/scans", response_model=ScanCreatedResponse)
async def create_versioned_scan(request: ScanRequest, background_tasks: BackgroundTasks, user: dict = Depends(current_user)):
    return await create_scan(request, user, background_tasks)


@app.get("/api/v1/scans", response_model=list[ScanRecord], response_model_exclude_unset=True)
async def get_scans(user: dict = Depends(current_user)):
    return tasks.list_scans(user)


@app.get("/api/v1/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, user: dict = Depends(current_user)):
    scan = tasks.get_scan(scan_id, user)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"scan_id": scan_id, "status": scan["status"]}


@app.get("/api/v1/scans/{scan_id}/results", response_model=Union[ScanResults, PendingResultsResponse], response_model_exclude_unset=True)
async def get_scan_results(scan_id: str, user: dict = Depends(current_user)):
    scan = tasks.get_scan(scan_id, user)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan["status"] != "completed":
        return {"scan_id": scan_id, "status": scan["status"], "results": None}
    import json
    return json.loads(scan["results_json"])


# Compatibility aliases. They retain the old paths but now require real authentication.
@app.post("/scans", response_model=ScanCreatedResponse)
async def legacy_create_scan(request: ScanRequest, background_tasks: BackgroundTasks, user: dict = Depends(current_user)):
    return await create_scan(request, user, background_tasks)


@app.get("/scans", response_model=list[ScanRecord], response_model_exclude_unset=True)
async def legacy_get_scans(user: dict = Depends(current_user)):
    return tasks.list_scans(user)


@app.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def legacy_get_scan_status(scan_id: str, user: dict = Depends(current_user)):
    return await get_scan_status(scan_id, user)


@app.get("/scans/{scan_id}/results", response_model=Union[ScanResults, PendingResultsResponse], response_model_exclude_unset=True)
async def legacy_get_scan_results(scan_id: str, user: dict = Depends(current_user)):
    return await get_scan_results(scan_id, user)
