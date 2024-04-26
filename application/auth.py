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


class Algorithms(StrEnum):
    """Colletion of Key Signing Algorithms."""

    RS256 = "RS256"
    HS256 = "HS256"


class _Claims(StrEnum):
    """Collection of important claims."""

    EMAIL = "email"
    PERMISSIONS = "permissions"
    SCOPE = "scope"
    SUBJECT = "sub"


class Token:
    """Token data returned from verify."""

    def __init__(
        self,
        *,
        email: str | None = None,
        permissions: list[str] | None = None,
        sub: str,
        **kwargs,
    ) -> None:
        self.id = self.sub = sub
        self.email = email
        self.permissions = permissions

        self.claims: dict[str, Any] = {"sub": sub}
        if email:
            self.claims["email"] = email
        if permissions:
            self.claims["permissions"] = permissions
        if kwargs:
            self.claims.update(kwargs)


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

        # ! setup JWKS client (Json Web Key Set), will use in `verify` function !
        # ! using PyJWT means no requests in `__init__()` ! YAAAYYY NO MORE MOCKING 🎉
        jwks_url = f"https://{self._domain}/.well-known/jwks.json"
        self._jwks_client = jwt.PyJWKClient(jwks_url)

        # Various OAuth2 Flows for OpenAPI interface
        params = urllib.parse.urlencode({"audience": self._api_audience})
        auth_url = f"https://{self._domain}/authorize?{params}"

        self.implicit_scheme = OAuth2ImplicitBearer(
            authorizationUrl=auth_url,
            scopes=scopes,
        )

        # TODO: uncomment and test later
        # self.authcode_scheme = OAuth2AuthorizationCodeBearer(
        #     authorizationUrl=auth_url,
        #     tokenUrl=f"https://{self._domain}/oauth/token",
        #     scopes=scopes,
        # )
        # self.password_scheme = OAuth2PasswordBearer(
        #     tokenUrl=f"https://{self._domain}/oauth/token", scopes=scopes
        # )
        # self.oidc_scheme = OpenIdConnect(
        #     openIdConnectUrl=f"https://{self._domain}/.well-known/openid-configuration"
        # )

    async def verify(
        self,
        security_scopes: SecurityScopes,
        token: HTTPAuthorizationCredentials | None = Depends(  # noqa: B008
            HTTPBearer(auto_error=False)  # noqa: B008
        ),
    ) -> Token:
        if token is None:
            raise UnauthorizedException

        try:
            # This gets the 'kid' from the passed token.
            # Netowrk request happens here.
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
        # self._check_claims(payload, _Claims.PERMISSIONS)
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
