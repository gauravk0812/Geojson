from typing import List, Optional
from fastapi_injector import Injected
from injector import inject


from core.contracts.icurrent_user_provider import ICurrentUserProvider
from core.contracts.ipermission_checker import IPermissionChecker
from core.exceptions.action_forbidden import ActionForbiddenException
from helpers.log import get_logger
from modules.user.schemas import User


logger = get_logger(__name__)


class PermissionCheckerImpl(IPermissionChecker):
    @inject
    def __init__(
        self,
        current_user_provider: ICurrentUserProvider = Injected(ICurrentUserProvider),
    ):
        self._current_user_provider = current_user_provider

    def ensure_permissions(
        self,
        all_of_permissions: Optional[List[str]] = None,
        any_of_permissions: Optional[List[str]] = None,
    ) -> None:
        """
        Verify if the current user has the necessary permissions to proceed.
        all_of_permissions: User must have every listed permission.
        any_of_permissions: User must have at least one listed permission.
        Raises exceptions if checks fail.
        """
        current_user: User = self._current_user_provider.get_user()
        if not current_user:
            raise ActionForbiddenException(
                detail="You don't have permission to perform this action."
            )
        # Get username using IUser's get_user_name method
        user_name = f"{current_user.first_name} {current_user.last_name}"

        if current_user.is_super_user or current_user.is_admin:
            return

        user_permissions = {perm.lower() for perm in current_user.get_permissions()}

        if all_of_permissions:
            required_all_permissions = [perm.lower() for perm in all_of_permissions]
            if not all(perm in user_permissions for perm in required_all_permissions):
                logger.warning(
                    f"Permission denied for user: '{user_name}'. Requires all: {', '.join(required_all_permissions)}"
                )  # add user details
                raise ActionForbiddenException(
                    detail="You don't have permission to perform this action."
                )

        if any_of_permissions:
            required_any_permissions = [perm.lower() for perm in any_of_permissions]
            if not any(perm in user_permissions for perm in required_any_permissions):
                logger.warning(
                    f"Permission denied for user: '{user_name}'. Requires one of: {', '.join(required_any_permissions)}"
                )
                raise ActionForbiddenException(
                    detail="You don't have permission to perform this action."
                )
