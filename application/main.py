"""Python FastAPI Auth0 integration example"""

from typing import Annotated, Any
from fastapi import Depends, FastAPI, Security
from application.auth import Auth0Token
from application.config import get_settings


settings = get_settings()
auth = Auth0Token(
    settings.auth0_api_audience,
    settings.auth0_domain,
    settings.auth0_issuer,
    {"read:message": "read messages"},
)

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


@app.get("/api/private", dependencies=[Depends(auth.implicit_scheme)])
async def private(auth_result: Annotated[Any, Security(auth.verify)]):
    """A valid access token is required to access this route"""
    return auth_result


@app.get("/api/private-scoped", dependencies=[Depends(auth.implicit_scheme)])
async def private_scoped(
    auth_result: Annotated[Any, Security(auth.verify, scopes=["read:message"])],
):
    """A valid access token and an appropriate scope are required to access
    this route
    """
    return auth_result
