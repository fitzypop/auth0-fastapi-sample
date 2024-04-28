import json
import os
import urllib
import urllib.request
from typing import Annotated

import pytest
from fastapi import HTTPException, Security, status
from fastapi.testclient import TestClient

from auth0_fastapi_sample.auth import Token
from auth0_fastapi_sample.main import app, verifier


@app.get("/test/token")
def token_endpoint(token: Annotated[Token, Security(verifier.verify)]):
    if token:
        return token.claims
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Something went wrong with token verifier",
    )


@app.get("/test/scoped")
def token_scoped_endpoint(
    token: Annotated[Token, Security(verifier.verify, scopes=["read:post"])],
):
    if token:
        return token.claims
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Something went wrong with token verifier",
    )


@pytest.fixture(scope="session")
def headers():
    request = urllib.request.Request(
        f"https://{os.environ["AUTH0_DOMAIN"]}/oauth/token",
        headers={"content-type": "application/json"},
        data=json.dumps(
            {
                "client_id": os.environ["AUTH0_CLIENT_ID"],
                "client_secret": os.environ["AUTH0_CLIENT_SECRET"],
                "audience": os.environ["AUTH0_API_AUDIENCE"],
                "grant_type": "client_credentials",
            }
        ).encode("utf-8"),
    )
    with urllib.request.urlopen(request) as response:
        data = json.loads(response.read())

    return {"Authorization": f"Bearer {data["token"]}"}


@pytest.mark.integration
def test_verifier_works(headers):
    client = TestClient(app)

    response = client.get("/test/token", headers=headers)
    assert response.status_code == 200, response.text

    response = client.get("/test/scoped", headers=headers)
    assert response.status_code == 200, response.text
