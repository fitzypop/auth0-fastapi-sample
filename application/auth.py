import urllib.parse
from enum import StrEnum
from typing import Any, Sequence

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
from pydantic import ValidationError


class UnauthorizedException(HTTPException):
    """Returns HTTP 401"""

    def __init__(self, detail: str = "Missing bearer token", **kwargs) -> None:
        super().__init__(status.HTTP_401_UNAUTHORIZED, detail, **kwargs)


class ForbiddenException(HTTPException):
    """Returns HTTP 403"""

    def __init__(self, detail: str, **kwargs) -> None:
        super().__init__(status.HTTP_403_FORBIDDEN, detail, **kwargs)


class OAuth2ImplicitBearer(OAuth2):
    """OAuth2 Implicit Bearer Flow repersentation.

    It's main function is to fetch Tokens from OpenAPI Authorize modal.

    Example usage:
    ```python
    auth = Auth0TokenVerifier(domain="", api_audience="", scopes={})
    app = FastAPI(dependencies=[Depends(auth.implicit_scheme)])
    ```
    or
    ```python
    @app.get("/", dependencies=[Depends(auth.implicit_scheme)])
    def func(): ...
    ```
    """

    def __init__(
        self,
        authorizationUrl: str,  # noqa: N803
        scopes: dict[str, str] | None = None,
        scheme_name: str | None = None,
        auto_error: bool = True,
    ) -> None:
        flows = OAuthFlows(
            implicit=OAuthFlowImplicit(
                authorizationUrl=authorizationUrl,
                scopes=scopes or {},
            )
        )
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> str | None:
        # Overload call method to prevent computational overhead.
        # The actual authentication is done in `Authenticator.verify`.
        # This is for OpenAPI Docs Authorize modal.
        return None


class AuthHTTPBearer(HTTPBearer):
    """Override HTTPBearer token handler.

    Some of the default errors don't make sense to me. This
    class attempts to recify my problems with the default.
    """

    def __init__(
        self,
        *,
        bearerFormat: str | None = None,  # noqa: N803
        scheme_name: str | None = "HTTPBearer",
        description: str | None = None,
        auto_error: bool = True,
    ) -> None:
        super().__init__(
            bearerFormat=bearerFormat,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        authorization = request.headers.get("Authorization")
        if not authorization:
            if self.auto_error:
                raise UnauthorizedException
            else:
                return None
        return await super().__call__(request)


class Algorithms(StrEnum):
    """Colletion of Key Signing Algorithms."""

    RS256 = "RS256"
    HS256 = "HS256"


class _Claims(StrEnum):
    """Collection of important claims."""

    EMAIL = "email"
    PERMISSION = "permission"
    SCOPE = "scope"
    SUBJECT = "sub"


class Token:
    """Token data returned from verify."""

    def __init__(
        self,
        *,
        email: str | None = None,
        permission: list[str] | None = None,
        sub: str,
        **kwargs,
    ) -> None:
        self.id = self.sub = sub
        self.permission = permission
        self.email = email
        self.claims = {
            "email": "email",
            "id": sub,
            "permission": permission,
            "sub": sub,
            **kwargs,
        }


class Auth0TokenVerifier:
    """Does all the token verification using PyJWT.

    Example Usage:
    ```python
    auth = Auth0TokenVerifier(...)
    app = FastAPI()

    @app.get("/")
    def index(token: Token = Security(auth.verify)):
        pass

    @app.get("/no_data", dependencies=[Security(auth.verify)])
    def get_no_token_data():
        pass

    @app.get("/scoped")
    def scoped_endpoint(token: Token = Security(auth.verify, scopes=["read:posts"])):
        pass

    @app.get(
        "/scoped_no_data",
        dependencies=[Security(auth.verify, scopes=["read:post"])],
        )
    def scoped_no_token_data():
        pass
    ```"""

    def __init__(
        self,
        *,
        algorithm: Algorithms = Algorithms.RS256,
        api_audience: str = "",
        domain: str = "",
        scopes: dict[str, str] | None = None,
    ) -> None:
        self._algorithms = [str(algorithm)]
        self._api_audience = api_audience
        self._domain = domain
        self._issuer = f"https://{domain}/"

        # ! gets JWKS (Json Web Key Set), will use in `verify` function !
        # ! using PyJWT means no requests in `__init__()` ! YAAAYYY NO MORE MOCKING 🎉
        jwks_url = f"https://{self._domain}/.well-known/jwks.json"
        self._jwks_client = jwt.PyJWKClient(jwks_url)

        if not scopes:
            scopes = {}

        # Various OAuth2 Flows for OpenAPI interface
        params = urllib.parse.urlencode({"audience": self._api_audience})
        auth_url = f"https://{self._domain}/authorize?{params}"
        self.authcode_scheme = OAuth2AuthorizationCodeBearer(
            authorizationUrl=auth_url,
            tokenUrl=f"https://{self._domain}/oauth/token",
            scopes=scopes,
        )
        self.implicit_scheme = OAuth2ImplicitBearer(
            authorizationUrl=auth_url,
            scopes=scopes,
        )
        self.password_scheme = OAuth2PasswordBearer(
            tokenUrl=f"https://{self._domain}/oauth/token", scopes=scopes
        )
        self.oidc_scheme = OpenIdConnect(
            openIdConnectUrl=f"https://{self._domain}/.well-known/openid-configuration"
        )

    async def verify(
        self,
        security_scopes: SecurityScopes,
        token: HTTPAuthorizationCredentials | None = Depends(AuthHTTPBearer()),  # noqa: B008
    ) -> Token:
        if token is None:
            raise UnauthorizedException

        try:
            # This gets the 'kid' from the passed token
            signing = self._jwks_client.get_signing_key_from_jwt(token.credentials)
        except (jwt.exceptions.PyJWKClientError, jwt.exceptions.DecodeError) as e:
            raise ForbiddenException(str(e)) from e

        try:
            payload: dict = jwt.decode(
                token.credentials,
                signing.key,
                algorithms=self._algorithms,
                audience=self._api_audience,
                issuer=self._issuer,
            )
        except Exception as e:
            raise ForbiddenException(str(e)) from e

        # ? not sure if this is needed? or might be occastional needed ?
        # self._check_claims(payload, ClaimNames.EMAIL)
        # self._check_claims(payload, _Claims.PERMISSION)
        self._check_claims(payload, _Claims.SUBJECT)

        if len(security_scopes.scopes) > 0:
            self._check_claims(payload, _Claims.SCOPE, security_scopes.scopes)

        try:
            return Token(**payload)
        except (ValidationError, ValueError) as e:
            raise UnauthorizedException(
                detail=f"Error parsing Auth0User: {str(e)}"
            ) from e

    def _check_claims(
        self,
        payload: dict,
        claim_name: _Claims,
        expected_value: Sequence[Any] | None = None,
    ) -> None:
        _claim_name = str(claim_name)

        if _claim_name not in payload:
            raise ForbiddenException(detail=f'No claim "{_claim_name}" found in token')

        if not expected_value:
            return

        payload_claim = (
            payload[_claim_name].split(" ")
            if claim_name == _Claims.SCOPE
            else payload[_claim_name]
        )

        for value in expected_value:
            if value not in payload_claim:
                raise ForbiddenException(detail=f'Missing "{value}" scope')
