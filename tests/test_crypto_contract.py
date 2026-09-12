from __future__ import annotations

import time

import jwt
import pytest
from pydantic import ValidationError

from tests.support.crypto_harness import EphemeralEs256Harness, UnknownKidError
from tests.support.fakes import FakeReplayDefense, FakeRevocationAuthority
from xcia.domain import ConfirmationClaim, RelyingPartyTrustPolicy
from xcia.services import AssertionTrustService, JwksPresenter, SenderBindingError
from xcia.services.assertions import ReplayRejectedError, RevokedSessionError


def test_es256_sign_and_verify(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    now = int(time.time())
    claims = harness.claims_with_binding(now=now)
    token = harness.sign(claims)
    verified = harness.verify(token, policy)
    assert verified == claims


def test_wrong_issuer_rejected(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    claims = harness.claims_with_binding(
        now=int(time.time()),
        issuer="urn:xafpay:customer-auth:staging",
    )
    with pytest.raises(jwt.InvalidIssuerError):
        harness.verify(harness.sign(claims), policy)


def test_wrong_audience_rejected(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    claims = harness.claims_with_binding(
        now=int(time.time()),
        audience="urn:xafpay:wallet-api:staging",
    )
    with pytest.raises(jwt.InvalidAudienceError):
        harness.verify(harness.sign(claims), policy)


def test_expired_assertion_rejected(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    now = int(time.time())
    claims = harness.claims_with_binding(
        now=now - 1_000,
        exp=now - 120,
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        harness.verify(harness.sign(claims), policy)


def test_future_nbf_beyond_skew_rejected(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    now = int(time.time())
    claims = harness.claims_with_binding(
        now=now,
        nbf=now + policy.clock_skew_seconds + 10,
        exp=now + 300,
    )
    with pytest.raises(jwt.ImmatureSignatureError):
        harness.verify(harness.sign(claims), policy)


def test_unknown_kid_rejected(policy: RelyingPartyTrustPolicy) -> None:
    signer = EphemeralEs256Harness()
    verifier = EphemeralEs256Harness(kid="test-kid-02")
    claims = signer.claims_with_binding(now=int(time.time()))
    with pytest.raises(UnknownKidError):
        verifier.verify(signer.sign(claims), policy)


def test_sender_binding_match_is_required(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    revocation = FakeRevocationAuthority()
    replay = FakeReplayDefense()
    service = AssertionTrustService(harness, revocation, replay)
    claims = harness.claims_with_binding(now=int(time.time()))
    token = harness.sign(claims)

    verified = service.validate(token=token, policy=policy, sender_jkt=harness.jkt)
    assert verified.cnf.jkt == harness.jkt


def test_sender_binding_mismatch_rejected(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    service = AssertionTrustService(
        harness,
        FakeRevocationAuthority(),
        FakeReplayDefense(),
    )
    token = harness.sign(harness.claims_with_binding(now=int(time.time())))
    with pytest.raises(SenderBindingError):
        service.validate(token=token, policy=policy, sender_jkt="different-thumbprint")


def test_revoked_sid_rejected(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    claims = harness.claims_with_binding(now=int(time.time()))
    revocation = FakeRevocationAuthority()
    revocation.revoked_sids.add(claims.sid)
    service = AssertionTrustService(harness, revocation, FakeReplayDefense())
    with pytest.raises(RevokedSessionError):
        service.validate(
            token=harness.sign(claims),
            policy=policy,
            sender_jkt=harness.jkt,
        )


def test_jti_replay_rejected(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    claims = harness.claims_with_binding(now=int(time.time()))
    service = AssertionTrustService(
        harness,
        FakeRevocationAuthority(),
        FakeReplayDefense(),
    )
    token = harness.sign(claims)

    service.validate(token=token, policy=policy, sender_jkt=harness.jkt)
    with pytest.raises(ReplayRejectedError):
        service.validate(token=token, policy=policy, sender_jkt=harness.jkt)


def test_jwks_serialization_is_public_only() -> None:
    harness = EphemeralEs256Harness()
    document = JwksPresenter(harness).document()
    assert len(document["keys"]) == 1
    key = document["keys"][0]
    assert "d" not in key
    assert "k" not in key
    assert key["alg"] == "ES256"
    assert key["kid"] == harness.kid


def test_cnf_jkt_is_required_by_claim_model(policy: RelyingPartyTrustPolicy) -> None:
    harness = EphemeralEs256Harness()
    now = int(time.time())
    claims = harness.claims_with_binding(now=now)
    payload = claims.model_dump()
    payload["cnf"] = {}
    with pytest.raises(ValidationError):
        # Pydantic rejects the absent required jkt before cryptographic verification.
        ConfirmationClaim.model_validate(payload["cnf"])
