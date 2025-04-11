from core.contracts.iuser_session_repository import IUserSessionRepository
from sqlalchemy.orm import Session


from injector import inject
from fastapi_injector import Injected

from core.contracts.icurrent_user_provider import ICurrentUserProvider
from core.contracts.idatetime_provider import IDateTimeProvider
from core.schemas.user_session import UserSession
from helpers.log import get_logger

from modules.authentication.models import ConfigModel, UserSessionModel
from core.generic_sql_repository import GenericSqlRepository

logger = get_logger(__name__)


class UserSessionRepositoryImpl(
    IUserSessionRepository, GenericSqlRepository[UserSession]
):
    """
    Implementation of the authentication repository interface.
    Handles database operations related to authentication.
    """

    @inject
    @inject
    def __init__(
        self,
        db_session: Session = Injected(Session),
        current_user_provider: ICurrentUserProvider = Injected(ICurrentUserProvider),
        date_time_provider: IDateTimeProvider = Injected(IDateTimeProvider),
    ) -> None:

        super().__init__(
            logger=logger,
            db_session=db_session,
            current_user_provider=current_user_provider,
            date_time_provider=date_time_provider,
            item_schema=UserSession,
            item_db_model=UserSessionModel,
        )

    def get_by_refresh_token(self, refresh_token: str) -> UserSession:
        """
        Retrieves a session by its refresh token.
        """
        user_session_model = (
            self._db_session.query(UserSessionModel)
            .filter(UserSessionModel.refresh_token == refresh_token)
            .first()
        )
        if user_session_model:
            user_session = self._to_schema(user_session_model)
            return user_session

        return None

    def get_secret_key(self) -> str:
        """
        Retrieves the secret key used for encoding and decoding JWT tokens.
        """
        config_item = (
            self._db_session.query(ConfigModel)
            .filter(ConfigModel.param_name == "SECRET_KEY")
            .first()
        )
        if config_item:
            return config_item.param_value

        return None

    def is_dummy_login_enabled(self) -> bool:
        """
        Retrieves True/False for username and password access for dummy login.
        """
        config_item = (
            self._db_session.query(ConfigModel)
            .filter(ConfigModel.param_name == "IS_DUMMY_LOGIN_ENABLED")
            .first()
        )
        if config_item:
            value: str = config_item.param_value
            if value is not None and value:
                value = value.strip().lower()
                return self._str_to_bool(value)
        return False

    def get_token_life(self) -> int:
        """
        Retrieves the token life duration from the configuration.
        Defaults to 30 minutes if not found.
        """
        token_life = 20  # default

        config_item = (
            self._db_session.query(ConfigModel)
            .filter_by(param_name="TOKEN_LIFE")
            .first()
        )
        if config_item:
            token_life = int(config_item.param_value)

        return token_life

    def _str_to_bool(self, value: str) -> bool:
        """
        Converts a string to a boolean.
        """
        if value.strip().lower() == "true":
            return True

        else:
            False

    # def get_session_by_id(self, session_id: str) -> UserSession:
    #     """
    #     Retrieves a session by its ID.
    #     """
    #     user_session_model = self._db.query(UserSessionModel).filter(UserSessionModel.session_id == session_id).first()
    #     if user_session_model:
    #         user_session = self._to_schema(user_session_model)
    #         return user_session

    #     return None

    # def create_session(
    #     self,
    #     user_id: UUID,
    #     client_ip: str,
    #     user_agent: str,
    #     login_method: str,
    # ) -> UserSession:
    #     """
    #     Creates a new session for the user and generates a refresh token.
    #     """
    #     refresh_token = secrets.token_urlsafe(32)
    #     user_session_model = UserSessionModel(
    #         user_id=user_id,
    #         client_ip=client_ip,
    #         user_agent=user_agent,
    #         status="active",
    #         refresh_token=refresh_token,
    #         logged_in_through=login_method,
    #     )
    #     self._preprocess_resource(user_session_model, b_adding=True)
    #     self._db.add(user_session_model)

    #     user_session = self._to_schema(user_session_model)
    #     return user_session

    # def update_session(self, user_session: UserSession) -> UserSession:
    #     """
    #     Updates the session status in the database.
    #     """
    #     user_session_model = user_session # TODO convert to model
    #     self._db.commit()

    #     user_session = self._to_schema(user_session_model)
    #     return user_session

    # def _to_schema(self, model: UserSessionModel) -> UserSession:
    #     user_session_dict = {
    #         **model.__dict__
    #     }

    #     return UserSession.model_construct(**user_session_dict)
