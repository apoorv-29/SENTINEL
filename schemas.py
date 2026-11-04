from typing import Optional

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    organization_name: str = Field(min_length=2, max_length=120)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("invalid email")
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: str = Field(min_length=20)


class UserResponse(BaseModel):
    id: str
    email: str
    organization_id: str
    role: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_url: AnyHttpUrl
    source_code: Optional[str] = Field(default=None, max_length=200_000)
    response_headers: Optional[dict[str, str]] = None

    @field_validator("response_headers")
    @classmethod
    def limit_headers(cls, value: Optional[dict[str, str]]) -> Optional[dict[str, str]]:
        if value is not None and (len(value) > 100 or any(len(k) > 256 or len(v) > 8192 for k, v in value.items())):
            raise ValueError("response headers exceed limits")
        return value


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


class Finding(BaseModel):
    title: str
    severity: str
    category: str
    description: str


class GraphNode(BaseModel):
    id: str
    label: str
    severity: str
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


class PendingResultsResponse(BaseModel):
    scan_id: str
    status: str
    results: Optional[ScanResults] = None


class ScanRecord(BaseModel):
    scan_id: str
    target: str
    status: str
    results: Optional[ScanResults] = None
    error: Optional[str] = None
