from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse
from .schemas import AuthenticationResponse, LoginRequest
from .auth_service import oauth2_scheme
from injector import inject
from fastapi_injector import Injected
from fastapi_utils.cbv import cbv
from core.contracts.iauth_service import IAuthService

auth_router = APIRouter(prefix="/auth")


@cbv(auth_router)
class auth_controller:

    @inject
    def __init__(self, auth_service: IAuthService = Injected(IAuthService)) -> None:
        self._auth_service = auth_service

    '''
    @auth_router.get("/login")
    async def sso_login(self, request: Request):
        """
        Initiates the SSO login process.
        Redirects the user to the SSO provider's login page.
        """
        callback_url = await self._auth_service.sso_login(request)
        if callback_url:
            return RedirectResponse(url=callback_url)
        else:
            return {"msg": "error"}
    '''

    @auth_router.post("/login")
    async def login(
        self, request: Request, login_request: LoginRequest
    ) -> AuthenticationResponse:
        """
        Authenticates the user using username and password.
        Creates a new session and returns an access token.
        """
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent")

        return self._auth_service.login(
            login_request.username, login_request.password, client_ip, user_agent
        )

    @auth_router.get("/logout", status_code=status.HTTP_200_OK)
    async def logout(self, token: str = Depends(oauth2_scheme)):
        """
        Logs out the user by invalidating the session associated with the given token.
        """
        self._auth_service.logout(token)
        return {"detail": "Successfully logged out"}

    @auth_router.post("/refresh-token/{refresh_token}")
    def refresh_token(self, refresh_token: str) -> AuthenticationResponse:
        """
        Refreshes the access token using a valid refresh token.
        """
        result = self._auth_service.refresh_access_token(refresh_token)
        return result

    # Debug acs endpoint to test SAML response locally.

    @auth_router.post("/debug/saml/acs")
    async def debug_acs(self, request: Request, email: str):
        response = await self._auth_service.debug_acs(request, email)
        return response


#####################################################################
# Special handling of saml login -

saml_router = APIRouter(prefix="/saml")


@cbv(saml_router)
class saml_auth_controller:

    @inject
    def __init__(self, auth_service: IAuthService = Injected(IAuthService)) -> None:
        self._auth_service = auth_service

    @saml_router.post("/acs")
    async def acs(self, request: Request):
        """
        Handles the SAML assertion consumer service (ACS) endpoint.
        Processes the SAML response from the SSO provider.
        """
        response = await self._auth_service.acs(request)
        return response
