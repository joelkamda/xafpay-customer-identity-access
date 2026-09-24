from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, NoReturn

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.domain import DurableSessionSnapshot
from xcia.policies import BrowserSecurityPolicy
from xcia.relying_party import WalletRelyingPartyProfile
from xcia.services import (
    AuthenticationDenied,
    CustomerPinAuthenticationService,
    DurableAssertionIssuer,
    DurableReadiness,
    HandoffDeniedError,
    HandoffServiceAuthenticationError,
    HandoffUnavailableError,
    JwksPresenter,
    PhoneProofRequired,
    SenderConstraintError,
    TrustedWalletSessionContext,
    UntrustedSessionError,
    WalletSessionHandoffService,
)
from xcia.services.jwks import PrivateKeyExposureError


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
    auth_completion_id: str
    handoff_code: str
    handoff_expires_at: datetime


class WalletHandoffRedeemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    handoff_code: str = Field(min_length=32, max_length=512)
    sender_jkt: str = Field(min_length=16, max_length=256)


class WalletHandoffReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_completion_id: str = Field(min_length=8, max_length=255)
    sender_jkt: str = Field(min_length=16, max_length=256)


class WalletHandoffResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    auth_completion_id: str
    xcia_session_cookie_name: str
    xcia_session_cookie_value: str
    auth_time: datetime
    sender_jkt: str
    security_version: int
    authoritative_xcia_idle_expires_at: datetime
    authoritative_xcia_absolute_expires_at: datetime


class LogoutResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["logged_out"] = "logged_out"


class WalletAssertionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender_jkt: str = Field(min_length=16, max_length=256)


class WalletAssertionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assertion: str
    token_type: Literal["DPoP"] = "DPoP"
    expires_in: Literal[300] = 300


class PublicJwksResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    keys: list[dict[str, object]]


def create_app(
    settings: XciaSettings | None = None,
    readiness: DurableReadiness | None = None,
    authentication: CustomerPinAuthenticationService | None = None,
    wallet_assertion_issuer: DurableAssertionIssuer | None = None,
    wallet_jwks: JwksPresenter | None = None,
    wallet_session_handoff: WalletSessionHandoffService | None = None,
) -> FastAPI:
    resolved = settings if settings is not None else XciaSettings.from_environment()
    BrowserSecurityPolicy(
        cookie_name=resolved.session_cookie_name,
        samesite=resolved.session_cookie_samesite,
    )
    wallet_profile = WalletRelyingPartyProfile.from_settings(resolved)
    if wallet_assertion_issuer is not None:
        issuer_settings = wallet_assertion_issuer.settings
        if (
            issuer_settings.issuer != wallet_profile.issuer
            or issuer_settings.audience != wallet_profile.audience
            or issuer_settings.assertion_lifetime_seconds
            != wallet_profile.assertion_lifetime_seconds
        ):
            raise ValueError("Wallet assertion issuer trust configuration mismatch")

    app = FastAPI(title="XafPay XCIA", version="0.2.0")
    app.state.xcia_settings = resolved
    app.state.wallet_relying_party_profile = wallet_profile

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

    def require_wallet_assertion_issuer() -> DurableAssertionIssuer:
        if wallet_assertion_issuer is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Wallet relying-party assertion service unavailable",
            )
        return wallet_assertion_issuer

    def require_wallet_jwks() -> JwksPresenter:
        if wallet_jwks is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Wallet relying-party JWKS unavailable",
            )
        return wallet_jwks

    def require_wallet_handoff() -> WalletSessionHandoffService:
        if wallet_session_handoff is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Wallet trusted handoff unavailable",
            )
        return wallet_session_handoff

    def trusted_origin(request: Request) -> str:
        origin = request.headers.get("origin")
        if origin not in resolved.trusted_origins:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        return origin

    def presented_service_token(request: Request) -> str:
        authorization = request.headers.get("authorization", "")
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
        token = authorization[len(prefix):]
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
        return token

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

    def authentication_response(
        request: Request,
        session: DurableSessionSnapshot,
    ) -> AuthenticationResponse:
        snapshot = session
        handoff = require_wallet_handoff().issue(
            session=snapshot,
            trusted_origin=trusted_origin(request),
        )
        return AuthenticationResponse(
            auth_completion_id=handoff.auth_completion_id,
            handoff_code=handoff.handoff_code,
            handoff_expires_at=handoff.handoff_expires_at,
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

    @app.post(
        "/bff/relying-parties/wallet/assertion",
        response_model=WalletAssertionResponse,
    )
    def wallet_assertion(
        request: Request,
        body: WalletAssertionRequest,
    ) -> WalletAssertionResponse:
        require_bff_request(request)
        sid = request.cookies.get(resolved.session_cookie_name)
        if sid is None:
            deny_authentication()
        issuer = require_wallet_assertion_issuer()
        try:
            assertion = issuer.issue(sid=sid, sender_jkt=body.sender_jkt)
        except UntrustedSessionError:
            deny_authentication()
        except SenderConstraintError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="forbidden",
            ) from exc
        return WalletAssertionResponse(
            assertion=assertion,
            expires_in=300,
        )

    @app.get("/.well-known/jwks.json", response_model=PublicJwksResponse)
    def public_jwks() -> PublicJwksResponse:
        presenter = require_wallet_jwks()
        try:
            document = presenter.document()
        except PrivateKeyExposureError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWKS unavailable",
            ) from exc
        return PublicJwksResponse.model_validate(document)

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
        return authentication_response(request, result.session)

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
        return authentication_response(request, result.session)

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
        return authentication_response(request, result.session)

    @app.post("/bff/auth/device/step-up", response_model=AuthenticationResponse)
    def device_step_up(
        request: Request,
        response: Response,
        body: PinLoginRequest,
    ) -> AuthenticationResponse:
        return pin_login(request, response, body)

    def handoff_response(context: TrustedWalletSessionContext) -> WalletHandoffResponse:
        return WalletHandoffResponse(
            auth_completion_id=context.auth_completion_id,
            xcia_session_cookie_name=context.xcia_session_cookie_name,
            xcia_session_cookie_value=context.xcia_session_cookie_value,
            auth_time=context.auth_time,
            sender_jkt=context.sender_jkt,
            security_version=context.security_version,
            authoritative_xcia_idle_expires_at=context.authoritative_xcia_idle_expires_at,
            authoritative_xcia_absolute_expires_at=context.authoritative_xcia_absolute_expires_at,
        )

    @app.post(
        "/internal/relying-parties/wallet/session-handoffs/redeem",
        response_model=WalletHandoffResponse,
    )
    def redeem_wallet_handoff(
        request: Request,
        body: WalletHandoffRedeemRequest,
    ) -> WalletHandoffResponse:
        service = require_wallet_handoff()
        try:
            context = service.redeem(
                handoff_code=body.handoff_code,
                sender_jkt=body.sender_jkt,
                trusted_origin=trusted_origin(request),
                presented_service_token=presented_service_token(request),
            )
        except HandoffServiceAuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            ) from exc
        except HandoffDeniedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="handoff_denied",
            ) from exc
        except HandoffUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="handoff_unavailable",
            ) from exc
        return handoff_response(context)

    @app.post(
        "/internal/relying-parties/wallet/session-handoffs/reconcile",
        response_model=WalletHandoffResponse,
    )
    def reconcile_wallet_handoff(
        request: Request,
        body: WalletHandoffReconcileRequest,
    ) -> WalletHandoffResponse:
        service = require_wallet_handoff()
        try:
            context = service.reconcile(
                auth_completion_id=body.auth_completion_id,
                sender_jkt=body.sender_jkt,
                trusted_origin=trusted_origin(request),
                presented_service_token=presented_service_token(request),
            )
        except HandoffServiceAuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            ) from exc
        except HandoffDeniedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="handoff_denied",
            ) from exc
        except HandoffUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="handoff_unavailable",
            ) from exc
        return handoff_response(context)

    @app.post("/bff/auth/logout", response_model=LogoutResponse)
    def logout(
        request: Request,
        response: Response,
    ) -> LogoutResponse:
        require_bff_request(request)
        sid = request.cookies.get(resolved.session_cookie_name)
        if sid is not None:
            service = require_authentication()
            service.sessions.revoke_session(sid)
        response.delete_cookie(
            key=resolved.session_cookie_name,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return LogoutResponse()

    return app
