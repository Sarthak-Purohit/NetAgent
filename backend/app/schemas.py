from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List
import datetime
import re

import ipaddress
import socket

class ScanBase(BaseModel):
    target: str
    profile: str

class ScanCreate(ScanBase):
    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        if v not in {"quick", "full", "targeted"}:
            raise ValueError("Invalid scan profile")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Target is required")
        if len(cleaned) > 256:
            raise ValueError("Input string exceeds maximum allowed length")
        if not re.match(r"^[a-zA-Z0-9\.\-\/:]+$", cleaned):
            raise ValueError("Invalid IP address format")
        
        # IP / target format check: if it is a dotted string (like 999.999.999.999 or abc.def.ghi.jkl),
        # check if it's a valid IP address, valid CIDR range, or a resolvable host.
        # If not, raise ValueError("Invalid IP address format").
        if len(cleaned.split('.')) == 4:
            is_valid_ip = False
            try:
                ipaddress.ip_address(cleaned)
                is_valid_ip = True
            except ValueError:
                pass

            is_valid_cidr = False
            try:
                ipaddress.ip_network(cleaned, strict=False)
                is_valid_cidr = True
            except ValueError:
                pass

            is_resolvable = False
            try:
                socket.getaddrinfo(cleaned, None)
                is_resolvable = True
            except Exception:
                pass

            if not (is_valid_ip or is_valid_cidr or is_resolvable):
                raise ValueError("Invalid IP address format")

        return cleaned

class ScanResponse(BaseModel):
    id: int
    target: str
    profile: str
    status: str
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True

class ScanResultResponse(BaseModel):
    id: int
    scan_id: int
    port: int
    protocol: str
    state: str
    status: str
    service: Optional[str] = None
    banner: Optional[str] = None
    vulnerability: Optional[str] = None
    vulnerabilities: Optional[List[str]] = None

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def deserialize_vulnerabilities(cls, v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            return v.strip().split(" | ")
        return v

    class Config:
        from_attributes = True

class ScanResultsWrapper(BaseModel):
    ports: List[ScanResultResponse] = []
    class Config:
        from_attributes = True

class ScanDetailResponse(ScanResponse):
    results: Optional[ScanResultsWrapper] = None

    @model_validator(mode="before")
    @classmethod
    def wrap_results(cls, data):
        if isinstance(data, dict):
            if "results" in data and isinstance(data["results"], list):
                data = dict(data)
                data["results"] = {"ports": data["results"]}
            return data
        elif hasattr(data, "results"):
            results = getattr(data, "results")
            if isinstance(results, list):
                data_dict = {}
                for field in cls.model_fields:
                    if field == "results":
                        data_dict["results"] = {"ports": results}
                    elif hasattr(data, field):
                        data_dict[field] = getattr(data, field)
                return data_dict
        return data

    class Config:
        from_attributes = True

class AlertBase(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    alert_type: str
    description: str
    severity: str

class AlertCreate(AlertBase):
    pass

class AlertResponse(AlertBase):
    id: int
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class CaptureRequest(BaseModel):
    action: str
    interface: Optional[str] = None

class PCAPAnalysisResponse(BaseModel):
    status: str
    filename: str
    alerts_generated: int
    alerts: List[AlertResponse]


class ExplainRequest(BaseModel):
    source_type: str
    source_id: int


class ExplainResponse(BaseModel):
    explanation: str
    severity: str
    remediation: str

    class Config:
        from_attributes = True


# --- Agent Session Schemas ---

class AgentSessionCreate(BaseModel):
    target: str
    profile: str = "quick"

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        if v not in {"quick", "full", "targeted"}:
            raise ValueError("Invalid scan profile")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Target is required")
        return cleaned

class AgentStepResponse(BaseModel):
    id: int
    session_id: int
    step_number: int
    action_type: str
    title: str
    description: Optional[str] = None
    status: str
    result_data: Optional[str] = None
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

class AgentSessionResponse(BaseModel):
    id: int
    target: str
    profile: str
    status: str
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    steps: List[AgentStepResponse] = []

    class Config:
        from_attributes = True

class AgentSessionSummary(BaseModel):
    id: int
    target: str
    profile: str
    status: str
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None
    steps_count: int = 0

    class Config:
        from_attributes = True

# --- Chatbot Schemas ---

class ChatMessage(BaseModel):
    role: str  # system, user, assistant
    content: str

class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []

class ChatResponse(BaseModel):
    response: str

