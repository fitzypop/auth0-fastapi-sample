"""Python FastAPI Auth0 integration example"""

from typing import Annotated, Any
from fastapi import FastAPI, Security
from application.auth import Auth0Token

# Creates app instance
app = FastAPI()
token = Auth0Token()

Token = Annotated[Any, Security(token.verify)]


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


@app.get("/api/private")
async def private(auth_result: Token):
    """A valid access token is required to access this route"""
    return auth_result


@app.get("/api/private-scoped")
async def private_scoped(auth_result=Security(token.verify, scopes=["read:message"])):
    """A valid access token and an appropriate scope are required to access
    this route
    """
    return auth_result
