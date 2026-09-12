from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from xcia.config import XciaSettings
from xcia.policies import BrowserSecurityPolicy


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["live", "ready"]
    environment: str


def create_app(settings: XciaSettings | None = None) -> FastAPI:
    resolved = settings if settings is not None else XciaSettings.from_environment()
    BrowserSecurityPolicy(
        cookie_name=resolved.session_cookie_name,
        samesite=resolved.session_cookie_samesite,
    )

    app = FastAPI(title="XafPay XCIA", version="0.1.0")
    app.state.xcia_settings = resolved

    @app.get("/health/live", response_model=HealthResponse)
    def health_live() -> HealthResponse:
        return HealthResponse(status="live", environment=resolved.environment.value)

    @app.get("/health/ready", response_model=HealthResponse)
    def health_ready() -> HealthResponse:
        return HealthResponse(status="ready", environment=resolved.environment.value)

    return app
