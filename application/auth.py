import urllib.parse
from enum import StrEnum, auto
from typing import Any, Dict, Optional, Sequence

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlowImplicit, OAuthFlows
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2,
    OAuth2AuthorizationCodeBearer,
    OAuth2PasswordBearer,
    OpenIdConnect,
    SecurityScopes,
)
from pydantic import BaseModel, EmailStr, Field, ValidationError


class ForbiddenException(HTTPException):
    def __init__(self, detail: str, **kwargs) -> None:
        """Returns HTTP 403"""
        super().__init__(status.HTTP_403_FORBIDDEN, detail, **kwargs)


class UnauthorizedException(HTTPException):
    def __init__(self, detail: str = "Missing bear token", **kwargs) -> None:
        """Returns HTTP 401"""
        super().__init__(status.HTTP_401_UNAUTHORIZED, detail, **kwargs)


class OAuth2ImplicitBearer(OAuth2):
    def __init__(
        self,
        authorizationUrl: str,  # noqa: N803
        scopes: Dict[str, str] | None = None,
        scheme_name: Optional[str] = None,
        auto_error: bool = True,
    ):
        flows = OAuthFlows(
            implicit=OAuthFlowImplicit(
                authorizationUrl=authorizationUrl,
                scopes=scopes or {},
            )
        )
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        # Overwrite parent call to prevent useless overhead.
        # The actual auth is done in Auth0.get_user
        # This scheme is just for Swagger UI
        return None


auth0_rule_namespace = "something"


class Auth0User(BaseModel):
    id: str = Field(..., alias="sub")
    permission: Optional[list[str]] = None
    email: Optional[EmailStr] = Field(None, alias=f"{auth0_rule_namespace}/email")


class Auth0HTTPBearer(HTTPBearer):
    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        authorization = request.headers.get("Authorization")
        if not authorization:
            if self.auto_error:
                raise UnauthorizedException
            else:
                return None
        return await super().__call__(request)


class Algorithms(StrEnum):
    RS256 = auto()
    HS256 = auto()


class ClaimNames(StrEnum):
    SCOPE = "scope"
    EMAIL = "email"


class Authenticator:
    """Does all the token verification using PyJWT"""

    def __init__(
        self,
        domain: str,
        api_audience: str,
        scopes: dict[str, str],
        *,
        algorithm: Algorithms = Algorithms.RS256,
    ) -> None:
        self._algorithms = [str(algorithm)]
        self._api_audience = api_audience
        self._domain = domain
        self._issuer = f"https://{domain}/"

        # This gets the JWKS from a given URL and does processing so you can
        # use any of the keys available
        jwks_url = f"https://{self._domain}/.well-known/jwks.json"
        self._jwks_client = jwt.PyJWKClient(jwks_url)

        # Various OAuth2 Schemas for OpenAPI interface
        params = urllib.parse.urlencode({"audience": self._api_audience})
        authorization_url = f"https://{self._domain}/authorize?{params}"
        self.implicit_scheme = OAuth2ImplicitBearer(
            authorizationUrl=authorization_url,
            scopes=scopes,
            scheme_name="Auth0ImplicitBearer",
        )
        self.password_scheme = OAuth2PasswordBearer(
            tokenUrl=f"https://{self._domain}/oauth/token", scopes=scopes
        )
        self.authcode_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=authorization_url,
            tokenUrl=f"https://{self._domain}/oauth/token",
            scopes=scopes,
        )
        self.oidc_scheme = OpenIdConnect(
            openIdConnectUrl=f"https://{self._domain}/.well-known/openid-configuration"
        )

    async def verify(
        self,
        security_scopes: SecurityScopes,
        token: Optional[HTTPAuthorizationCredentials] = Depends(Auth0HTTPBearer()),  # noqa: B008
    ) -> Auth0User:
        if token is None:
            raise UnauthorizedException

        try:
            # This gets the 'kid' from the passed token
            signing = self._jwks_client.get_signing_key_from_jwt(token.credentials)
        except (jwt.exceptions.PyJWKClientError, jwt.exceptions.DecodeError) as e:
            raise ForbiddenException(str(e)) from e

        try:
            payload = jwt.decode(
                token.credentials,
                signing.key,
                algorithms=self._algorithms,
                audience=self._api_audience,
                issuer=self._issuer,
            )
        except Exception as e:
            raise ForbiddenException(str(e)) from e

        if len(security_scopes.scopes) > 0:
            self._check_claims(payload, ClaimNames.SCOPE, security_scopes.scopes)

        # ? not sure if this is needed? or might be occastional needed ?
        # self._check_claims(payload, ClaimNames.EMAIL)

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
            raise ForbiddenException(detail=f'No claim "{_claim_name}" found in token')

        if not expected_value:
            return

        payload_claim = (
            payload[_claim_name].split(" ")
            if claim_name == ClaimNames.SCOPE
            else payload[_claim_name]
        )

        for value in expected_value:
            if value not in payload_claim:
                raise ForbiddenException(detail=f'Missing "{value}" scope')
