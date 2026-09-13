from __future__ import annotations

from typing import Literal

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict

from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.policies import BrowserSecurityPolicy
from xcia.services import DurableReadiness


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["live", "ready"]
    environment: str


def create_app(
    settings: XciaSettings | None = None,
    readiness: DurableReadiness | None = None,
) -> FastAPI:
    resolved = settings if settings is not None else XciaSettings.from_environment()
    BrowserSecurityPolicy(
        cookie_name=resolved.session_cookie_name,
        samesite=resolved.session_cookie_samesite,
    )

    app = FastAPI(title="XafPay XCIA", version="0.2.0")
    app.state.xcia_settings = resolved

    @app.get("/health/live", response_model=HealthResponse)
    def health_live() -> HealthResponse:
        return HealthResponse(status="live", environment=resolved.environment.value)

    @app.get("/health/ready", response_model=HealthResponse)
    def health_ready() -> HealthResponse:
        operational_environment = resolved.environment in {
            RuntimeEnvironment.STAGING,
            RuntimeEnvironment.PRODUCTION,
        }
        if operational_environment and readiness is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable readiness dependencies are not configured",
            )
        if readiness is not None and not readiness.is_ready():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable readiness dependencies are not ready",
            )
        return HealthResponse(status="ready", environment=resolved.environment.value)

    return app
