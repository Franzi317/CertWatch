"""API request/response schemas. Response models deliberately omit channel
secrets (SMTP password, webhook URL) so they're never exposed via the API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class TargetIn(BaseModel):
    name: str
    description: str = ""
    target_type: str
    value: str
    ports: list[int] = Field(default_factory=lambda: [443])
    environment: str = "prod"
    owner: str = ""
    tags: list[str] = Field(default_factory=list)
    scan_frequency_minutes: int = 1440
    schedule_type: str = "interval"      # interval | daily | weekly | monthly
    schedule_time: str = "00:00"         # "HH:MM" in the app timezone (calendar types)
    schedule_day: int = 0                # weekly: 0=Mon..6=Sun; monthly: 1..28
    timeout: float = 5.0
    concurrency: int = 50
    enabled: bool = True
    alert_thresholds: list[int] = Field(default_factory=lambda: [90, 60, 30, 14, 7, 1])
    use_sni: bool = True


class TargetOut(TargetIn):
    id: int
    last_scanned_at: datetime | None = None
    created_at: datetime
    endpoint_count: int = 0
    model_config = {"from_attributes": True}


class ScanJobOut(BaseModel):
    id: int
    target_id: int | None
    target_name: str
    status: str
    trigger: str
    total_endpoints: int
    scanned_endpoints: int
    certs_found: int
    errors: int
    message: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    model_config = {"from_attributes": True}


class ChannelIn(BaseModel):
    name: str
    channel_type: str  # smtp | teams | webhook
    enabled: bool = True
    config: dict = Field(default_factory=dict)
    re_alert_hours: int = 24


class ChannelOut(BaseModel):
    id: int
    name: str
    channel_type: str
    enabled: bool
    re_alert_hours: int
    # config scrubbed of secrets; only non-sensitive keys echoed back
    config_summary: dict = Field(default_factory=dict)


class TestNotifyIn(BaseModel):
    channel_id: int


class IssuerIn(BaseModel):
    name: str
    issuer_type: str  # adcs | acme
    enabled: bool = True
    config: dict = Field(default_factory=dict)


class IssuerOut(BaseModel):
    id: int
    name: str
    issuer_type: str
    enabled: bool
    last_test_at: datetime | None = None
    last_test_ok: bool = False
    created_at: datetime
    # config scrubbed of secrets; only non-sensitive keys + "<key>_set" markers
    config: dict = Field(default_factory=dict)


class AlertActionIn(BaseModel):
    mute_hours: int | None = None  # for mute; None = indefinite
