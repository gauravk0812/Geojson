from datetime import timedelta
from typing import List, Optional, Tuple
from uuid import UUID
from injector import inject
from fastapi_injector import Injected


from core.base_data_filter import BaseDataFilter
from core.contracts.inew_hire_tracking_repository import INewHireTrackingRepository
from core.contracts.ipermission_checker import IPermissionChecker

from core.contracts.istaff_repository import IStaffRepository
from core.contracts.istaff_service import IStaffService
from core.generic_service import GenericService

from core.schemas.pagination_response import PaginationResponse
from helpers.log import get_logger
from modules.staff.schemas import (
    Staff,
    StaffDeleteOnboarding,
)
from modules.new_hire_tracking.schemas import NewHireTrackingCreate
from modules.staff.staff_filter import StaffFilter, StaffProximityFilter
from .schemas import (
    Staff,
    StaffHistory,
    StaffHistoryCreate,
    StaffUpdate,
    UserProfileUpdate,
)

logger = get_logger(__name__)


class StaffService(IStaffService, GenericService[Staff]):
    @inject
    def __init__(
        self,
        staff_repository: IStaffRepository = Injected(IStaffRepository),
        new_hire_repository: INewHireTrackingRepository = Injected(
            INewHireTrackingRepository
        ),
        permission_checker: IPermissionChecker = Injected(IPermissionChecker),
    ):
        """
        Constructor
        """
        super().__init__(Staff, staff_repository, permission_checker)

        self._staff_repository: IStaffRepository = staff_repository
        self._new_hire_repository: INewHireTrackingRepository = new_hire_repository

    def _validate_and_set_sorting(
        self, sort_on: Optional[str], sort_ascending: Optional[bool]
    ) -> Tuple[str, bool]:
        """
        Validate and set sorting parameters.

        Args:
            sort_on (Optional[str]): The field to sort on.
            sort_ascending (Optional[bool]): Whether to sort in ascending order.

        Returns:
            Tuple[str, bool]: The validated sorting field and order.
        """
        # Default sorting on first_name.
        if sort_on is None:
            sort_on = "first_name"
        if sort_ascending is None:
            sort_ascending = True

        # Convert sort_on to lowercase
        if sort_on:
            sort_on = sort_on.lower()

        return sort_on, sort_ascending

    def find(self, data_filter: BaseDataFilter) -> PaginationResponse[Staff]:
        # Set default sort field if none provided
        required_permissions = self._get_permissions_to_view()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )

        staff_filter: StaffFilter = data_filter

        staff_filter.sort_on, staff_filter.sort_ascending = (
            self._validate_and_set_sorting(
                staff_filter.sort_on, staff_filter.sort_ascending
            )
        )
        return super().find(data_filter)

    def get_staff_in_proximity(
        self, data_filter: StaffProximityFilter
    ) -> PaginationResponse[Staff]:
        required_permissions = self._get_permissions_to_view()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )

        return self._staff_repository.get_staff_in_proximity(data_filter)

    def staff_history_create(self, staff: StaffHistoryCreate) -> StaffHistory:
        required_permissions = self._get_permissions_to_create()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )
        return self._staff_repository.staff_history_create(staff)

    def update(self, id: UUID, staff: StaffUpdate) -> Optional[Staff]:
        required_permissions = self._get_permissions_to_modify()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )
        return self._staff_repository.update(id, staff)

    def update_user_profile(
        self, id: UUID, staff: UserProfileUpdate
    ) -> Optional[Staff]:
        required_permissions = self._get_permissions_to_modify()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )
        return self._staff_repository.update_user_profile(id, staff)

    def delete(self, id: UUID, date: StaffDeleteOnboarding) -> Optional[Staff]:
        required_permissions = self._get_permissions_to_delete()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )
        # Get staff details
        staff_info = self.get_by_id(id)

        # Update last_date if not set
        if staff_info.last_date is None:
            staff_info.last_date = date.last_date

        # Determine direct manager
        direct_manager_tid = (
            staff_info.manager_tid
            if staff_info.assoc_manager_tid == staff_info.manager_tid
            else staff_info.assoc_manager_tid
        )

        # Create new hire tracking record
        new_hire_info = NewHireTrackingCreate(
            x_emp_id=staff_info.emp_id,
            x_first_name=staff_info.first_name,
            x_last_name=staff_info.last_name,
            zone=staff_info.zone,
            team=staff_info.team,
            city=staff_info.home_city,
            state=staff_info.home_state,
            direct_manager_tid=direct_manager_tid,
            req_number=None,
            req_type=None,
            phone_interviews=None,
            f2f_interviews=None,
            qualified_candidates=None,
            new_hire_first_name=None,
            new_hire_last_name=None,
            tentative_start_date=None,
            req_date=(
                staff_info.last_date + timedelta(days=1)
                if staff_info.last_date
                else None
            ),
            actual_start_date=None,
            offer_rate=None,
            training_week=None,
            req_status="Wait",
            new_hire_status="Talk To Director First",
            comments=None,
            is_new_position=False,
            is_deleted=False,
        )

        # Create new hire record
        self._new_hire_repository.create(new_hire_info)

        # Delete staff and return
        return self._staff_repository.delete(id, date)

    def _get_permissions_to_view(self) -> List[str]:
        return ["STAFF.VIEW", "STAFF.ADD", "STAFF.MODIFY", "STAFF.DELETE"]

    def _get_permissions_to_create(self) -> List[str]:
        return ["STAFF.ADD"]

    def _get_permissions_to_modify(self) -> List[str]:
        return ["STAFF.MODIFY"]

    def _get_permissions_to_delete(self) -> List[str]:
        return ["STAFF.DELETE"]
