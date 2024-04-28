import sqlite3
from enum import StrEnum

from authlib.jose import jwt
from fastapi import FastAPI
from pydantic import BaseModel, SecretStr

connection = sqlite3.connect("fake_auth0.db")

app = FastAPI()


class GrantTypes(StrEnum):
    CLIENT = "client_credentials"


class TokenIn(BaseModel):
    client_id: str
    client_secret: SecretStr
    audience: str
    grant_type: GrantTypes


@app.get("/test/auth0_api_data")
def get_api_data():
    return {
        "AUTH0_API_AUDIENCE": "",
        "AUTH0_CLIENT_ID": "",
        "AUTH0_CLIENT_SECRET": "",
        "AUTH0_DOMAIN": "",
    }


class Algorithms(StrEnum):
    RS256 = "RS256"
    HS256 = "HS256"


@app.get("/oauth/token")
def get_token(token_in: TokenIn):
    # alg: focus on RS256, since that's what we currently user.
    alg = Algorithms.HS256
    alg_str = str(alg)
    headers = {
        "alg": alg_str,
        "typ": "JWT",
        "kid": "Some random string",
    }
    permissions = ["user:read", "user:read:me"]
    payload = {
        "exp": "(Expiration Time) unix datetime",
        "nbf": "(Not Before Time) unix datetime",
        "iss": "(Issuer) Auth0_Domain",
        "aud": "(Audience) Auth0_API_Audience",
        "iat": "(Issued At) unix datetime",
        "sub": "Auth0 User Id",
        "scope": " ".join(permissions),
        "permissions": permissions,
    }
    new_key = jwt.encode(headers, payload, "secret")
    return {"token": new_key}


@app.get("/.well-known/jwks.json")
def get_jwks():
    return {"keys": []}
