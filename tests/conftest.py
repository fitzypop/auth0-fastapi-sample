from unittest.mock import AsyncMock

import pytest

from application.auth import Auth0TokenVerifier


@pytest.fixture
def mock_verify():
    mock_thing = AsyncMock(Auth0TokenVerifier)
    mock_thing.verify = AsyncMock(return_value="fake_result_data")
    return mock_thing
