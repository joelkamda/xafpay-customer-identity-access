from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, NoReturn

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict

from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.policies import BrowserSecurityPolicy
from xcia.services import (
    AuthenticationDenied,
    CustomerPinAuthenticationService,
    DurableReadiness,
    PhoneProofRequired,
)


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["live", "ready"]
    environment: str


class PhoneStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phone: str


class PhoneProofRequest(PhoneStartRequest):
    challenge_id: str
    proof: str


class PinAuthenticationRequest(PhoneProofRequest):
    pin: str
    sender_jkt: str
    device_id: str


class PinLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phone: str
    pin: str
    sender_jkt: str
    device_id: str
    step_up_challenge_id: str | None = None
    step_up_proof: str | None = None


class ChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: str


class VerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["verified"] = "verified"


class AuthenticationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["authenticated"] = "authenticated"


def create_app(
    settings: XciaSettings | None = None,
    readiness: DurableReadiness | None = None,
    authentication: CustomerPinAuthenticationService | None = None,
) -> FastAPI:
    resolved = settings if settings is not None else XciaSettings.from_environment()
    BrowserSecurityPolicy(
        cookie_name=resolved.session_cookie_name,
        samesite=resolved.session_cookie_samesite,
    )

    app = FastAPI(title="XafPay XCIA", version="0.2.0")
    app.state.xcia_settings = resolved

    def require_bff_request(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin not in resolved.trusted_origins:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        if request.headers.get("x-xcia-csrf") != "required":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")

    def require_authentication() -> CustomerPinAuthenticationService:
        if authentication is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="authentication unavailable",
            )
        return authentication

    def set_session_cookie(response: Response, sid: str) -> None:
        response.set_cookie(
            key=resolved.session_cookie_name,
            value=sid,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )

    def deny_authentication() -> NoReturn:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication_failed",
        )

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

    @app.post("/bff/auth/enrollment/start", response_model=ChallengeResponse)
    def enrollment_start(request: Request, body: PhoneStartRequest) -> ChallengeResponse:
        require_bff_request(request)
        service = require_authentication()
        try:
            challenge_id = service.start_phone_verification(body.phone, now=datetime.now(UTC))
        except ValueError:
            deny_authentication()
        return ChallengeResponse(challenge_id=challenge_id)

    @app.post("/bff/auth/phone/verify", response_model=VerificationResponse)
    def phone_verify(request: Request, body: PhoneProofRequest) -> VerificationResponse:
        require_bff_request(request)
        service = require_authentication()
        try:
            service.verify_phone_proof(body.challenge_id, body.proof, now=datetime.now(UTC))
        except (AuthenticationDenied, ValueError):
            deny_authentication()
        return VerificationResponse()

    @app.post("/bff/auth/enrollment/complete", response_model=AuthenticationResponse)
    def enrollment_complete(
        request: Request,
        response: Response,
        body: PinAuthenticationRequest,
    ) -> AuthenticationResponse:
        require_bff_request(request)
        service = require_authentication()
        try:
            result = service.enroll(
                phone=body.phone,
                challenge_id=body.challenge_id,
                proof=body.proof,
                pin=body.pin,
                sender_jkt=body.sender_jkt,
                device_id=body.device_id,
            )
        except (AuthenticationDenied, ValueError):
            deny_authentication()
        set_session_cookie(response, result.session.sid)
        return AuthenticationResponse()

    @app.post("/bff/auth/login", response_model=AuthenticationResponse)
    def pin_login(
        request: Request,
        response: Response,
        body: PinLoginRequest,
    ) -> AuthenticationResponse:
        require_bff_request(request)
        service = require_authentication()
        client_ip = request.client.host if request.client is not None else "unknown"
        try:
            result = service.login(
                phone=body.phone,
                pin=body.pin,
                sender_jkt=body.sender_jkt,
                device_id=body.device_id,
                ip_address=client_ip,
                step_up_challenge_id=body.step_up_challenge_id,
                step_up_proof=body.step_up_proof,
            )
        except (AuthenticationDenied, PhoneProofRequired, ValueError):
            deny_authentication()
        set_session_cookie(response, result.session.sid)
        return AuthenticationResponse()

    @app.post("/bff/auth/recovery/start", response_model=ChallengeResponse)
    def recovery_start(request: Request, body: PhoneStartRequest) -> ChallengeResponse:
        return enrollment_start(request, body)

    @app.post("/bff/auth/recovery/verify", response_model=VerificationResponse)
    def recovery_verify(request: Request, body: PhoneProofRequest) -> VerificationResponse:
        return phone_verify(request, body)

    @app.post("/bff/auth/recovery/complete", response_model=AuthenticationResponse)
    def recovery_complete(
        request: Request,
        response: Response,
        body: PinAuthenticationRequest,
    ) -> AuthenticationResponse:
        require_bff_request(request)
        service = require_authentication()
        try:
            result = service.recover(
                phone=body.phone,
                challenge_id=body.challenge_id,
                proof=body.proof,
                new_pin=body.pin,
                sender_jkt=body.sender_jkt,
                device_id=body.device_id,
            )
        except (AuthenticationDenied, ValueError):
            deny_authentication()
        set_session_cookie(response, result.session.sid)
        return AuthenticationResponse()

    @app.post("/bff/auth/device/step-up", response_model=AuthenticationResponse)
    def device_step_up(
        request: Request,
        response: Response,
        body: PinLoginRequest,
    ) -> AuthenticationResponse:
        return pin_login(request, response, body)

    return app
