import uuid
from injector import inject
from fastapi_injector import Injected

from datetime import timedelta, timezone, datetime, time
import json
import secrets
import xmltodict
from urllib.parse import urlencode
from uuid import UUID


from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from core.contracts.iauth_service import IAuthService
import jwt
from fastapi.security import OAuth2PasswordBearer
from core.contracts.istaff_repository import IStaffRepository
from core.exceptions.action_forbidden import ActionForbiddenException
from core.exceptions.not_authorized_exception import NotAuthorizedException
import base64
from core.exceptions.not_found_exception import NotFoundException
from helpers.log import get_logger
from modules.user.schemas import User
from core.schemas.user_session import UserSession

# from saml import init_saml_auth, prepare_from_fastapi_request
from core.contracts.iuser_session_repository import IUserSessionRepository
from core.contracts.iuser_repository import IUserRepository


logging = get_logger(__name__)

ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class AuthenticationService(IAuthService):
    """
    Authentication service implements the business logic layer for authentication module.
    It is responsible for access control and business rules validations.
    It does not interact with the database directly. It uses the
    authentication repository for that purpose.
    """

    @inject
    def __init__(
        self,
        auth_repository: IUserSessionRepository = Injected(IUserSessionRepository),
        user_repository: IUserRepository = Injected(IUserRepository),
        staff_repository: IStaffRepository = Injected(IStaffRepository),
    ):
        """
        Constructor
        """
        self.user_session_repository = auth_repository
        self.user_repository = user_repository
        self.staff_repository = staff_repository

    def login(self, username: str, password: str, client_ip: str, user_agent: str):
        """
        Logs in a user by creating a session and generating an access token.
        """

        # Check if username and password login is allowed using the repository method
        if not self.user_session_repository.is_dummy_login_enabled():
            raise NotFoundException(detail="URL not found")

        user: User = self._authenticate_user(username, password)

        expires_at = self._get_token_expiry_time()

        user_session: UserSession = self._create_user_session_instance(
            user_id=user.id,
            user_agent=user_agent,
            client_ip=client_ip,
            session_mode="username and password",
        )

        user_session = self.user_session_repository.create(user_session)

        access_token: str = self._create_access_token(
            user=user, user_session=user_session, expires_at=expires_at
        )
        # Get staff_id
        staff = self.staff_repository.get_by_email(user.email)
        staff_id = staff.id if staff else None
        # Update the user object with the staff_id
        user.staff_id = staff_id

        return {
            "user": user,
            "access_token": access_token,
            # The isoformat() method then converts this datetime object to a string in ISO 8601 format.
            # which is a standard way to represent date and time.
            "expires_at": expires_at.isoformat(),  # Returns expire time in ISO format
            "session_id": str(user_session.id),
            "refresh_token": user_session.refresh_token,
        }

    def refresh_access_token(self, refresh_token: str):
        """
        Refreshes the access token using a valid refresh token.
        Raises an exception if the refresh token is invalid or expired.
        """
        user_session: UserSession = self.user_session_repository.get_by_refresh_token(
            refresh_token
        )
        if not user_session or user_session.status != "active":
            raise NotAuthorizedException(detail="Invalid or expired refresh token")

        user: User = self.user_repository.get_by_id(user_session.user_id)

        expires_at = self._get_token_expiry_time()

        # Generate a new refresh token
        new_refresh_token = secrets.token_urlsafe(32)
        user_session.refresh_token = new_refresh_token
        self.user_session_repository.update(user_session)

        new_access_token = self._create_access_token(
            user=user, user_session=user_session, expires_at=expires_at
        )

        # Get staff_id
        staff = self.staff_repository.get_by_email(user.email)
        staff_id = staff.id if staff else None
        # Update the user object with the staff_id
        user.staff_id = staff_id
        return {
            "user": user,
            "access_token": new_access_token,
            # The isoformat() method then converts this datetime object to a string in ISO 8601 format.
            # which is a standard way to represent date and time.
            "expires_at": expires_at.isoformat(),  # Returns expire time in ISO format
            "session_id": str(user_session.id),
            "refresh_token": user_session.refresh_token,
        }

    def logout(self, token: str):
        """
        Logs out the user by invalidating the session associated with the given token.
        """
        try:
            secret_key = self.user_session_repository.get_secret_key()

            payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
            session_id_str = payload.get("session_id")
            session_id: UUID = UUID(session_id_str)
            user_session: UserSession = self.user_session_repository.get_by_id(
                session_id
            )
            if user_session:
                user_session.logout_at = (datetime.now(timezone.utc),)
                user_session.status = "logged_out"
                self.user_session_repository.update(user_session)

        except jwt.ExpiredSignatureError:
            payload = jwt.decode(
                token,
                secret_key,
                algorithms=[ALGORITHM],
                options={"verify_exp": False},
            )
            session_id_str = payload.get("session_id")
            session_id: UUID = UUID(session_id_str)
            user_session: UserSession = self.user_session_repository.get_by_id(
                session_id
            )
            if user_session:
                user_session.status = "expired"
                self.user_session_repository.update(user_session)
        except jwt.DecodeError:
            raise NotAuthorizedException(detail="Could not decode token")
        except jwt.InvalidTokenError:
            raise NotAuthorizedException(detail="Invalid token")

    '''
    async def sso_login(self, request: Request):
        """
        Initiates the SSO login process using SAML authentication.
        """
        req = await prepare_from_fastapi_request(request)
        auth = init_saml_auth(req)
        return auth.login()
    '''

    async def acs(self, request: Request):

        email: str = await self._extract_email_from_request(request=request)
        if not email:
            raise ActionForbiddenException(detail="Authentication Failed")

        user: User = self.user_repository.get_by_email(email)
        if not user:
            raise ActionForbiddenException(detail="Authentication Failed")

        user_roles = self.user_repository.get_user_roles(user.id)

        client_ip = request.client.host
        user_agent = request.headers.get("user-agent")

        user_session: UserSession = self._create_user_session_instance(
            user_id=user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            session_mode="SAML",
        )
        user_session = self.user_session_repository.create(user_session)

        expires_at = self._get_token_expiry_time()
        access_token = self._create_access_token(
            user=user, user_session=user_session, expires_at=expires_at
        )

        # Access the client_url from the SAML settings
        client_url = "/saml"

        # Assuming user.roles is a list of role objects with a 'name' attribute
        roles = [role.name for role in user_roles] if user_roles else []
        roles_json = json.dumps(roles)

        # Get staff_id
        staff = self.staff_repository.get_by_email(user.email)
        staff_id = staff.id if staff else None

        # Create the dictionary of query parameters
        params = {
            "user_name": user.user_name,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "tech_id": user.tech_id,
            "full_name": user.full_name,
            "email": user.email,
            "is_admin": user.is_admin,
            "is_super_user": user.is_super_user,
            "id": user.id,
            "roles": roles_json,
            "zone": user.zone,
            "access_token": access_token,
            "session_id": str(user_session.id),
            "refresh_token": user_session.refresh_token,
            "expires_at": expires_at.isoformat(),
            "user_type": user.user_type,
            "staff_id": staff_id,
        }

        # Encode the query parameters
        query_param = urlencode(params)

        # Construct the redirect URL
        redirect_url = f"{client_url}?{query_param}"
        # print(redirect_url)

        # Return the RedirectResponse
        return RedirectResponse(url=redirect_url)

    async def debug_acs(self, request: Request, email: str):
        # Simulate SAML response
        saml_attributes = {"email": [email]}

        user: User = self.user_repository.get_by_email(email)
        if not user:
            raise ActionForbiddenException(detail="Authentication Failed")

        user_roles = self.user_repository.get_user_roles(user.id)

        client_ip = request.client.host
        user_agent = request.headers.get("user-agent")

        user_session = self._create_user_session_instance(
            user_id=user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            session_mode="SAML",
        )
        user_session = self.user_session_repository.create(user_session)

        expires_at = self._get_token_expiry_time()
        access_token = self._create_access_token(
            user=user, user_session=user_session, expires_at=expires_at
        )

        # Access the client_url from the SAML settings
        client_url = "/saml"

        # Assuming user.roles is a list of role objects with a 'name' attribute
        roles = [role.name for role in user_roles] if user.roles else []
        roles_json = json.dumps(roles)

        # Get staff_id
        staff = self.staff_repository.get_by_email(user.email)
        staff_id = staff.id if staff else None

        # Create the dictionary of query parameters
        params = {
            "user_name": user.user_name,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "tech_id": user.tech_id,
            "full_name": user.full_name,
            "user_type": user.user_type,
            "email": user.email,
            "is_admin": user.is_admin,
            "is_super_user": user.is_super_user,
            "id": user.id,
            "roles": roles_json,
            "zone": user.zone,
            "access_token": access_token,
            "session_id": str(user_session.id),
            "refresh_token": user_session.refresh_token,
            "expires_at": expires_at.isoformat(),
            "staff_id": staff_id,
        }

        # Encode the query parameters
        query_param = urlencode(params)

        # Construct the redirect URL
        redirect_url = f"{client_url}?{query_param}"
        # print(redirect_url)

        # Return the user information and tokens
        user_dict = None  # TODO why is user dictionary required?

        return {
            "user": user_dict,
            "access_token": access_token,
            "session_id": str(user_session.id),
            "refresh_token": user_session.refresh_token,
            "expires_at": expires_at.isoformat(),
            "staff_id": staff_id,
        }

    def get_current_user(self, token: str = Depends(oauth2_scheme)):
        try:
            # Decode the token
            secret_key = self.user_session_repository.get_secret_key()
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            username: str = payload.get("username")
            email: str = payload.get("email")
            if username is None or email is None:
                raise NotAuthorizedException(
                    detail="Could not validate user credentials."
                )
            return {"username": username, "email": email}
        except jwt.ExpiredSignatureError:
            raise NotAuthorizedException(detail="Token has expired.")
        except jwt.DecodeError:
            raise NotAuthorizedException(detail="Could not decode token.")
        except jwt.InvalidTokenError:
            raise NotAuthorizedException(detail="Invalid token.")

    def _create_user_session_instance(
        self, user_id: str, client_ip: str, user_agent: str, session_mode: str
    ) -> UserSession:

        refresh_token = secrets.token_urlsafe(32)

        session_id = uuid.uuid4()
        user_session = UserSession(
            session_id=session_id,
            user_id=user_id,
            client_ip=client_ip,
            user_agent=user_agent,
            status="active",
            refresh_token=refresh_token,
            logged_in_at=datetime.now(timezone.utc),
            logged_in_through=session_mode,
        )

        return user_session

    def _authenticate_user(self, username: str, password: str):
        """
        Authenticates a user by username and password.
        Raises an exception if authentication fails.
        """
        user = self.user_repository.get_by_user_name(username)
        if not user:
            raise NotAuthorizedException(
                detail="Invalid User Credentials.", no_rollback=True
            )
        if user.user_name != password:
            raise NotAuthorizedException(
                detail="Invalid User Credentials.", no_rollback=True
            )
        return user

    def _create_access_token(
        self, user: User, user_session: UserSession, expires_at: datetime
    ):
        """
        Creates a JWT access token with the given user details and expiration time.
        """
        secret_key = self.user_session_repository.get_secret_key()
        current_time = current_time = datetime.utcnow()

        payload = {
            "user_id": str(user.id),
            "email": user.email,
            "session_id": str(user_session.id),
            "iat": current_time,
            "exp": expires_at,
        }

        return jwt.encode(payload, secret_key, ALGORITHM)

    def _get_token_expiry_time(self) -> datetime:
        token_life_minutes = self.user_session_repository.get_token_life()
        expires_delta = timedelta(minutes=token_life_minutes)
        current_time = current_time = datetime.utcnow()
        expires_at = current_time + expires_delta

        return expires_at

    async def _extract_email_from_request(self, request: Request) -> str:
        form_data = await request.form()
        data = form_data.get("SAMLResponse")

        if data:
            saml_response = xmltodict.parse(base64.b64decode(data))

            # Extract the email from the AttributeStatement
            attributes = saml_response["samlp:Response"]["saml:Assertion"][
                "saml:AttributeStatement"
            ]["saml:Attribute"]
            try:
                email = next(
                    attr["saml:AttributeValue"]["#text"]
                    for attr in attributes
                    if attr["@Name"] == "email"
                )
                return email
            except StopIteration:
                return None

        return None
