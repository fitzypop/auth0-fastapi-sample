import contextlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from application.auth import Auth0TokenVerifier


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
    with get_mock_jwt_decode({"sub": "test_user", "other": "value"}) as mock_jwt_decode:
        verify = Auth0TokenVerifier()
        token = await verify.verify(
            MagicMock(),
            HTTPAuthorizationCredentials(scheme="bearer", credentials="token"),
        )

        assert mock_jwk_client.called
        assert mock_jwt_decode.called
        assert token is not None
        assert token.sub == "test_user"
        assert token.claims == {"sub": "test_user", "other": "value"}
