from typing import List, Type, Generic, TypeVar, Optional
from uuid import UUID

from core.contracts.igeneric_service import IGenericService
from core.base_data_filter import BaseDataFilter
from core.contracts.ipermission_checker import IPermissionChecker
from core.exceptions.not_found_exception import NotFoundException
from core.contracts.igeneric_repository import IGenericRepository
from core.schemas.pagination_response import PaginationResponse
from core.schemas.fts_linq_base_schemas import FtsLinqBaseSchema

T = TypeVar("T", bound=FtsLinqBaseSchema)  # domain model


class GenericService(Generic[T], IGenericService[T]):
    """
    Generic service class that provides implementation of common plumbing for CRUD
    operation.
    Ref: https://dev.to/manukanne/a-python-implementation-of-the-unit-of-work-and-repository-design-pattern-using-sqlmodel-3mb5
    """

    def __init__(
        self,
        item_schema: Type[T],
        repository: IGenericRepository[T],
        permission_checker: IPermissionChecker,
    ) -> None:
        """:
        Constructor
        """
        self._item_schema = item_schema  # domain model
        self._repository = repository
        self._permission_checker = permission_checker

    def get_by_id(self, id: UUID) -> T:
        required_permissions = self._get_permissions_to_view()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )

        item = self._repository.get_by_id(id)
        if item is None:
            raise NotFoundException(detail="Invalid id specified.")

        return item

    def find(self, data_filter: BaseDataFilter = None) -> PaginationResponse[T]:
        """
        Public method to get paginated list of items matching the
        specified filter criterion.
        """
        required_permissions = self._get_permissions_to_view()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )

        result = self._repository.find(data_filter)
        return result

    def create(self, item: T) -> T:
        """
        Public method to add a new item.
        """
        required_permissions = self._get_permissions_to_create()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )

        item = self._repository.create(item)
        return item

    def update(self, id: UUID, item: T) -> Optional[T]:
        """
        Public method to update an existing item.
        """
        required_permissions = self._get_permissions_to_modify()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )

        self._ensure_valid_id(id)
        item.id = id

        item = self._repository.update(item)
        return item

    def delete(self, id: UUID) -> None:
        """
        Public method to delete the item identified by specified id.
        """
        required_permissions = self._get_permissions_to_delete()
        if required_permissions:
            self._permission_checker.ensure_permissions(
                any_of_permissions=required_permissions
            )

        self._ensure_valid_id(id)

        self._repository.delete(id)

    def _ensure_valid_id(self, id: UUID):
        """
        Protected helper method to ensure that the specified id represents
        a valid item.

        Raises:
            Exception: Raises exception if the specified id does not represent
            a valid item id.
        """
        item = self._repository.get_by_id(id)
        if item is None:
            raise NotFoundException(detail="Invalid id specified.")

        return item

    def _get_permissions_to_create(self) -> List[str]:
        """
        Protected helper method to retrieve the list of permissions required to create an entity.

        Returns:
            List[str]: A list of permission strings required for creating an entity.
        """
        return None

    def _get_permissions_to_modify(self) -> List[str]:
        """
        Protected helper method to retrieve the list of permissions required to modify an entity.

        Returns:
            List[str]: A list of permission strings required for modifying an entity.
        """
        return None

    def _get_permissions_to_delete(self) -> List[str]:
        """
        Protected helper method to retrieve the list of permissions required to delete an entity.

        Returns:
            List[str]: A list of permission strings required for deleting an entity.
        """
        return None

    def _get_permissions_to_view(self) -> List[str]:
        """
        Protected helper method to retrieve the list of permissions required to view an entity.

        Returns:
            List[str]: A list of permission strings required for viewing an entity.
        """
        return None
