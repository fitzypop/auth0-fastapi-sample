"""Python FastAPI Auth0 integration example"""

from typing import Annotated, Any
from fastapi import Depends, FastAPI, Security
from application.auth import Authenticator
from application.config import get_settings

settings = get_settings()
auth = Authenticator(
    settings.auth0_domain,
    settings.auth0_api_audience,
    {"read:message": "read messages"},
)
Token = Annotated[Any, Security(auth.verify)]


def Scopes(*scopes: str):
    return Security(auth.verify, scopes=scopes)


app = FastAPI()


@app.get("/api/public")
async def public():
    """No access token required to access this route"""

    result = {
        "status": "success",
        "msg": (
            "Hello from a public endpoint! You don't need to be "
            "authenticated to see this."
        ),
    }
    return result


# use `Depends(auth.implicit_scheme)` to tell OpenAPI Docs to use OAuth2 Implicit Flow to get tokens
# use `Security(auth.verify)` to "lockdown" an endpoint
@app.get("/api/private", dependencies=[Depends(auth.implicit_scheme)])
async def private(auth_result: Token):
    """A valid access token is required to access this route"""
    return auth_result


@app.get("/api/private-scoped", dependencies=[Depends(auth.implicit_scheme)])
async def private_scoped(auth_result: Annotated[Any, Scopes("read:message")]):
    """A valid access token and an appropriate scope are required to access
    this route
    """
    return auth_result
