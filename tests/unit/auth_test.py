import contextlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.security import HTTPAuthorizationCredentials, SecurityScopes

from auth0_fastapi_sample.auth import Algorithms, Auth0TokenVerifier, ForbiddenException


@pytest.fixture
def mock_jwk_client():
    with patch("jwt.PyJWKClient") as jwk_client_mock:
        jwk_client_mock.return_value.get_signing_key_from_jwt.return_value = MagicMock()
        yield jwk_client_mock


@contextlib.contextmanager
def get_mock_jwt_decode(payload: dict[str, Any]):
    with patch("jwt.decode") as decode_jwt_mock:
        decode_jwt_mock.return_value = payload
        yield decode_jwt_mock


@pytest.mark.asyncio
async def test_mocks_work(mock_jwk_client):
    payload = {"sub": "test_user", "permissions": [], "scope": ""}
    verify = Auth0TokenVerifier()
    with get_mock_jwt_decode(payload) as mock_jwt_decode:
        token = await verify.verify(
            MagicMock(),
            MagicMock(),
        )

    assert mock_jwk_client.called
    assert mock_jwt_decode.called
    assert token is not None
    assert token.sub == "test_user"
    assert token.claims == {"sub": "test_user", "scope": "", "permissions": []}


@pytest.mark.asyncio
async def test_scopes_work(mock_jwk_client):
    payload = {
        "sub": "test_user",
        "scope": "user:read user:read:me",
        "permissions": ["user:read", "user:read:me"],
    }
    verify = Auth0TokenVerifier()
    with get_mock_jwt_decode(payload) as mock_jwt_decode:
        token = await verify.verify(
            SecurityScopes(scopes=["user:read", "user:read:me"]),
            HTTPAuthorizationCredentials(scheme="bearer", credentials="token"),
        )

    assert mock_jwk_client.called
    assert mock_jwt_decode.called
    assert token is not None
    assert token.sub == "test_user"
    assert token.permissions == ["user:read", "user:read:me"]
    assert token.claims == {
        "sub": "test_user",
        "permissions": ["user:read", "user:read:me"],
        "scope": "user:read user:read:me",
    }


@pytest.mark.asyncio
async def test_missing_scope_throws_forbidden_status_code(mock_jwk_client):
    payload = {
        "sub": "test-user",
        "scope": "",
        "permissions": [""],
    }
    verifier = Auth0TokenVerifier(algorithm=Algorithms.HS256)
    with get_mock_jwt_decode(payload) as mock_jwt_decode, pytest.raises(
        ForbiddenException
    ):
        await verifier.verify(SecurityScopes(scopes=["garbage:scope"]), MagicMock())
    payload = {
        "sub": "test-user",
        "scope": "",
        "permissions": ["user:read", "admin_user:read"],
    }
    with get_mock_jwt_decode(payload) as mock_jwt_decode, pytest.raises(
        ForbiddenException
    ):
        await verifier.verify(
            SecurityScopes(scopes=["user:read", "garbage:scope"]), MagicMock()
        )

    assert mock_jwk_client.called
    assert mock_jwt_decode.called
