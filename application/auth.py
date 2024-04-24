from enum import StrEnum
from typing import Any, Optional, Sequence

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import SecurityScopes, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, ValidationError

from application.config import get_settings


class ForbiddenException(HTTPException):
    def __init__(self, detail: str, **kwargs) -> None:
        """Returns HTTP 403"""
        super().__init__(status.HTTP_403_FORBIDDEN, detail, **kwargs)


class UnauthorizedException(HTTPException):
    def __init__(self, detail: str, **kwargs) -> None:
        """Returns HTTP 401"""
        super().__init__(status.HTTP_401_UNAUTHORIZED, detail, **kwargs)


class ClaimNames(StrEnum):
    SCOPE = "scope"
    EMAIL = "email"


auth0_rule_namespace = "something"


class Auth0User(BaseModel):
    id: str = Field(..., alias="sub")
    permission: Optional[list[str]] = None
    email: Optional[EmailStr] = Field(None, alias=f"{auth0_rule_namespace}/email")


class Auth0HTTPBear(HTTPBearer):
    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        return await super().__call__(request)


class Auth0Token:
    """Does all the token verification using PyJWT"""

    def __init__(self) -> None:
        self.config = get_settings()
        self.auth0_algorithms = ["RS256"]

        # This gets the JWKS from a given URL and does processing so you can
        # use any of the keys available
        jwks_url = f"https://{self.config.auth0_domain}/.well-known/jwks.json"
        self.jwks_client = jwt.PyJWKClient(jwks_url)

    async def verify(
        self,
        security_scopes: SecurityScopes,
        token: Optional[HTTPAuthorizationCredentials] = Depends(Auth0HTTPBear()),
    ) -> Auth0User:
        if token is None:
            raise UnauthorizedException("Missing bearer token")

        # This gets the 'kid' from the passed token
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(
                token.credentials
            ).key
        except (jwt.exceptions.PyJWKClientError, jwt.exceptions.DecodeError) as error:
            raise ForbiddenException(str(error))

        try:
            payload = jwt.decode(
                token.credentials,
                signing_key,
                algorithms=self.auth0_algorithms,
                audience=self.config.auth0_api_audience,
                issuer=self.config.auth0_issuer,
            )
        except Exception as error:
            raise ForbiddenException(str(error))

        if len(security_scopes.scopes) > 0:
            self._check_claims(payload, ClaimNames.SCOPE, security_scopes.scopes)

        self._check_claims(payload, ClaimNames.EMAIL)

        try:
            return Auth0User(**payload)

        except ValidationError as e:
            raise UnauthorizedException(detail="Error parsing Auth0User") from e

    def _check_claims(
        self,
        payload,
        claim_name: ClaimNames,
        expected_value: Optional[Sequence[Any]] = None,
    ) -> None:
        _claim_name = str(claim_name)

        if _claim_name not in payload:
            raise ForbiddenException(detail=f'No claim "{claim_name}" found in token')

        payload_claim = (
            payload[_claim_name].split(" ")
            if claim_name == ClaimNames.SCOPE
            else payload[_claim_name]
        )

        if not expected_value:
            return

        for value in expected_value:
            if value not in payload_claim:
                raise ForbiddenException(detail=f'Missing "{claim_name}" scope')
