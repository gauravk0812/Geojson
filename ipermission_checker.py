from abc import ABC, abstractmethod
from typing import List, Optional


class IPermissionChecker(ABC):

    @abstractmethod
    def ensure_permissions(
        self,
        all_of_permissions: Optional[List[str]] = None,
        any_of_permissions: Optional[List[str]] = None,
    ) -> None:
        pass
