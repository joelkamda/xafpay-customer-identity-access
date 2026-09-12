from __future__ import annotations

from pydantic import BaseModel, ConfigDict, model_validator


class BrowserSecurityPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cookie_name: str = "__Host-xcia_session"
    httponly: bool = True
    secure: bool = True
    domain: None = None
    path: str = "/"
    samesite: str = "lax"
    csrf_required: bool = True
    exact_origin_validation: bool = True
    wildcard_credentialed_cors: bool = False

    @model_validator(mode="after")
    def enforce_frozen_baseline(self) -> BrowserSecurityPolicy:
        if not self.cookie_name.startswith("__Host-"):
            raise ValueError("cookie name must be __Host- compatible")
        if not self.httponly or not self.secure:
            raise ValueError("session cookie must be HttpOnly and Secure")
        if self.domain is not None:
            raise ValueError("__Host- cookie must omit Domain")
        if self.path != "/":
            raise ValueError("__Host- cookie Path must be /")
        if self.samesite.lower() != "lax":
            raise ValueError("XCIA1 SameSite baseline is Lax")
        if not self.csrf_required or not self.exact_origin_validation:
            raise ValueError("CSRF and exact Origin validation are required")
        if self.wildcard_credentialed_cors:
            raise ValueError("wildcard credentialed CORS is forbidden")
        return self
