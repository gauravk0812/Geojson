from datetime import datetime, timedelta, timezone
import os
import re
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pathlib import Path
from fastapi_injector import Injected
from injector import inject
from datetime import timedelta
from fastapi import File, UploadFile
from config import Config
import pandas as pd

from core.contracts.icurrent_user_provider import ICurrentUserProvider
from core.contracts.idocument_store_service import IDocumentStoreService
from core.contracts.iproject_execution_data_history_repository import (
    IProjectExecutionHistoryRepository,
)
from core.contracts.iproject_field_service import IProjectFieldService
from core.contracts.iuser_session_repository import IUserSessionRepository
from core.exceptions.bad_request_exception import BadRequestException
from core.exceptions.not_found_exception import NotFoundException
from core.schemas.pagination_response import PaginationResponse
from helpers.validate_date import ensure_valid_date
from modules.document_store.schemas import DocumentStoreCreate

from core.contracts.ipermission_checker import IPermissionChecker
from core.contracts.iproject2_repository import IProject2Repository
from core.contracts.iproject_recurrence_data_repository import IProjectRecurrenceDataRepository
from core.contracts.iproject2_service import IProject2Service
from core.contracts.iproject_execution_data_repository import (
    IProjectExecutionDataRepository,
)
from core.exceptions.validation_failed_exception import ValidationFailedException
from core.generic_service import GenericService

from modules.project2.project2_filter import ProjectMasterFilter
from modules.project2.project_execution_data_filter import ProjectExecutionDataFilter
from modules.project2.schemas import (
    CloneProjectRequest,
    ProjectData,
    ProjectFieldDefinitionUpdate,
    ProjectMaster,
    ProjectMasterCreate,
    ProjectReset,
    ProjectResetFinalizeRequest,
    ProjectResetFinalizeResponse,
    ProjectResetValidationRequest,
    ProjectResetValidationResponse,
)
from helpers.constants import (
    AZURE_BLOB,
    COMPLETED,
    FILE_SYSTEM,
    HALF_YEARLY,
    YEARLY,
    ONE_TIME,
    PENDING,
    QUARTERLY,
    MONTHLY,
    SPECIFIED_SITES,
    SPECIFIED_SITES_FROM_EXCEL,
    IS_TECHNICIAN,
    LEAD_TECHNICIAN,
)
from helpers.log import get_logger

logger = get_logger(__name__)
config = Config()
UPLOAD_DIRECTORY = Path(config.BASE_DOC_STORE_DIRECTORY)
UPLOAD_DIRECTORY.mkdir(exist_ok=True)


class Project2Service(IProject2Service, GenericService[ProjectMaster]):
    """
    Project service implements the business logic layer for Project module.
    It is responsible for access control and business rules validations.
    It does not interact with the database directly. It uses the
    Project repository for that purpose.
    """

    @inject
    def __init__(
        self,
        project2_repository: IProject2Repository = Injected(IProject2Repository),
        permission_checker: IPermissionChecker = Injected(IPermissionChecker),
        project_execution_data_repository: IProjectExecutionDataRepository = Injected(
            IProjectExecutionDataRepository
        ),
        project_execution_history_repository: IProjectExecutionHistoryRepository = Injected(
            IProjectExecutionHistoryRepository
        ),
        document_store_service: IDocumentStoreService = Injected(IDocumentStoreService),
        current_user_provider: ICurrentUserProvider = Injected(ICurrentUserProvider),
        project_field_service: IProjectFieldService = Injected(IProjectFieldService),
        user_repository: IUserSessionRepository = Injected(IUserSessionRepository),
        project_recurrence_repository: IProjectRecurrenceDataRepository = Injected(IProjectRecurrenceDataRepository),
    ):
        """
        Constructor
        """
        super().__init__(ProjectMaster, project2_repository, permission_checker)

        self._project2_repository: IProject2Repository = project2_repository
        self._project_recurrence_repository: IProjectRecurrenceDataRepository = project_recurrence_repository
        self._project_execution_data_repository: IProjectExecutionDataRepository = (
            project_execution_data_repository
        )
        self._project_execution_history_repository: (
            IProjectExecutionHistoryRepository
        ) = project_execution_history_repository
        self._project_field_service: IProjectFieldService = project_field_service
        self._document_store_service: IDocumentStoreService = document_store_service
        self._current_user_provider: ICurrentUserProvider = current_user_provider
        self._user_repository: IUserSessionRepository = user_repository

    def project_code_exists(self, project_code):
        return self._project2_repository.project_code_exists(project_code)

    def _process_project_dates_and_scope(self, item: ProjectMaster) -> None:
        if item:
            # Set end_date based on recurrence if not provided
            if not item.end_date:
                if item.recurrence == QUARTERLY:
                    item.end_date = item.start_date + timedelta(days=90)
                elif item.recurrence == HALF_YEARLY:
                    item.end_date = item.start_date + timedelta(days=182)
                elif item.recurrence == YEARLY:
                    item.end_date = item.start_date + timedelta(days=365)
                elif item.recurrence in (MONTHLY, ONE_TIME):
                    item.end_date = item.start_date + timedelta(days=30)
                    item.cycle_index = 1

            # if scope is Specified Sites from excel then extract sites from excel file
            if item.scope == SPECIFIED_SITES_FROM_EXCEL:
                # Step 4: Read file content from document store
                document_content = self._document_store_service.get_by_id(
                    item.scope_doc_id
                )
                # Step 5: Extract site names from the first column of the Excel file
                if document_content.storage_type == AZURE_BLOB:
                    extracted_sites = (
                        self._document_store_service.read_excel_from_azure(
                            blob_path=document_content.file_path,
                            sheet_name=document_content.sheet_name,
                        )
                    )

                if document_content.storage_type == FILE_SYSTEM:
                    extracted_sites = self.extract_sites_from_file_content(
                        document_content.file_path, document_content.sheet_name
                    )
                # Step 6: Valid site names
                item.scope_data = self._project2_repository.valid_sites(extracted_sites)

            # Validate exclusions if applicable
            self._validate_scope_exclusions(
                item.scope, item.scope_data, item.excluded_sites, item.additional_sites
            )

    def _validate_scope_exclusions(
        self,
        scope: Optional[str],
        scope_data: Optional[str],
        excluded_sites: Optional[str],
        additional_sites: Optional[str],
    ) -> None:
        """
        Validate if excluded sites intersect with scope data or additional sites.
        scope_data, excluded_sites, and additional_sites are comma-separated strings.
        """

        excluded_set = self._convert_to_set(excluded_sites)
        scope_set = self._convert_to_set(scope_data)
        additional_set = self._convert_to_set(additional_sites)

        def format_set(s: set) -> str:
            return ", ".join(sorted(s)) if s else "(none)"

        if scope in (SPECIFIED_SITES_FROM_EXCEL, SPECIFIED_SITES):
            # Check combined intersection
            combined_set = scope_set & additional_set
            if combined_set & excluded_set:
                raise ValidationFailedException(
                    detail=f"Excluded sites found in Site IDs and Additional Sites fields: {format_set(combined_set & excluded_set)}"
                )

            # Check intersections for scope_data and excluded_sites
            if scope_set & excluded_set:
                raise ValidationFailedException(
                    detail=f"Excluded sites found in Site IDs field: {format_set(scope_set & excluded_set)}"
                )

            # Check intersections for additional_sites and excluded_sites
            if additional_set & excluded_set:
                raise ValidationFailedException(
                    detail=f"Excluded sites found in Additional Sites field: {format_set(additional_set & excluded_set)}"
                )

        else:
            # For other scopes, only check additional_sites vs excluded_sites
            if additional_set & excluded_set:
                raise ValidationFailedException(
                    detail=f"Excluded Sites found in Additional Sites field: {format_set(additional_set & excluded_set)}"
                )

    def _convert_to_set(self, data: Optional[str]) -> set:
        return (
            set(site.strip() for site in data.split(",") if site and site.strip())
            if data
            else set()
        )

    def find(self, data_filter: ProjectMasterFilter) -> PaginationResponse[ProjectData]:
        self._validate_date_range(data_filter)

        # Validate cycle index if provided
        if data_filter.cycle_index and not data_filter.cycle_index.isdigit():
            raise ValidationFailedException(detail="Cycle index must be a numeric value")

        project_data_filter: ProjectMasterFilter = data_filter

        result = super().find(project_data_filter)
        return result

    def _validate_date_range(self, data_filter: ProjectMasterFilter):
        # Validate start and end dates
        if data_filter.start_date:
            data_filter.start_date = ensure_valid_date(data_filter.start_date)
        if data_filter.end_date:
            data_filter.end_date = ensure_valid_date(data_filter.end_date)
        if (
            data_filter.start_date
            and data_filter.end_date
            and data_filter.end_date < data_filter.start_date
        ):
            raise BadRequestException(
                detail="Project 'to date' should not be less than 'from date'"
            )

        # Validate cycle start and end dates
        if data_filter.cycle_start_date:
            data_filter.cycle_start_date = ensure_valid_date(
                data_filter.cycle_start_date
            )
        if data_filter.cycle_end_date:
            data_filter.cycle_end_date = ensure_valid_date(data_filter.cycle_end_date)
        if (
            data_filter.cycle_start_date
            and data_filter.cycle_end_date
            and data_filter.cycle_end_date < data_filter.cycle_start_date
        ):
            raise BadRequestException(
                detail="Cycle 'to date' should not be less than 'from date'"
            )

    def create(
        self,
        item: ProjectMaster,
    ) -> ProjectMaster:
        self._ensure_valid_project_name(item.name)
        self._ensure_unique_project_code(None, item)
        self._ensure_valid_project_type(item.project_type)

        self._process_project_dates_and_scope(item)

        item.cycle_start_date = item.start_date
        item.cycle_end_date = item.end_date
        item.cycle_index = 1

        self._set_complete_within_days_for_non_recurring_project(item)

        if item.scope_doc_id is not None:
            document_content = self._document_store_service.get_by_id(item.scope_doc_id)
            if document_content and document_content.status == "Temporary":
                self._update_document_status(item.scope_doc_id)
                # Once the scope file is finalized move it to final location in azure blob
                if document_content.storage_type == AZURE_BLOB:
                    file_path = f"Project/{item.project_code}/Scope/{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
                    self._document_store_service.move_document_to_final_location_in_azure(
                        id=item.scope_doc_id, destination_path=file_path
                    )

        created_item = super().create(item)
        self._project_execution_data_repository.create_recal_scope_sites(
            created_item.id
        )
        self._project_recurrence_repository.recalculate_recurrence_site_counts(
            created_item.id, created_item.cycle_index or 1
        )
        return created_item

    def update(self, id: UUID, item: ProjectMaster) -> ProjectMaster | None:

        self._ensure_valid_project_name(item.name)
        self._ensure_unique_project_code(id, item)
        self._ensure_valid_project_type(item.project_type)

        self._process_project_dates_and_scope(item)

        item.cycle_start_date = item.start_date
        item.cycle_end_date = item.end_date

        self._set_complete_within_days_for_non_recurring_project(item)

        if item.scope_doc_id is not None:
            document_content = self._document_store_service.get_by_id(item.scope_doc_id)
            if document_content and document_content.status == "Temporary":
                self._update_document_status(item.scope_doc_id)
                # Once the scope file is finalized move it to final location in azure blob
                if document_content.storage_type == AZURE_BLOB:
                    file_path = f"Project/{item.project_code}/Scope/{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
                    self._document_store_service.move_document_to_final_location_in_azure(
                        id=item.scope_doc_id, destination_path=file_path
                    )

        updated_item = super().update(id, item)
        self._project_execution_data_repository.create_recal_scope_sites(
            updated_item.id
        )
        if updated_item:
            self._project_recurrence_repository.recalculate_recurrence_site_counts(
                updated_item.id, updated_item.cycle_index or 1
            )
        return updated_item

    def _set_complete_within_days_for_non_recurring_project(
        self, item: ProjectMaster
    ) -> None:
        if item.recurrence == ONE_TIME:
            item.complete_within_days = (item.end_date - item.start_date).days

    def clone_project(
        self,
        request: CloneProjectRequest,
    ) -> ProjectMaster:
        """
        Create a new project by duplicating an existing project.
        """
        # Fetch the existing project
        existing_project = self._project2_repository.get_by_id(
            request.existing_project_id
        )
        if not existing_project:
            raise NotFoundException(f"Project with specified ID not found")

        # Validate the new project code is unique (case-insensitive)
        self._ensure_unique_project_code_for_cloned_project(request.project_code)

        # Create new project with duplicated details
        new_project_data = ProjectMasterCreate(
            name=request.name,
            display_name=request.display_name,
            description=existing_project.description,
            recurrence=existing_project.recurrence,
            start_date=existing_project.start_date,
            end_date=existing_project.end_date,
            complete_within_days=existing_project.complete_within_days,
            scope=existing_project.scope,
            scope_data=existing_project.scope_data,
            estimated_execution_time=existing_project.estimated_execution_time,
            category=existing_project.category,
            sites_completed=existing_project.sites_completed,
            sites_on_projects=existing_project.sites_on_projects,
            cycle_start_date=existing_project.cycle_start_date,
            cycle_end_date=existing_project.cycle_end_date,
            cycle_index=existing_project.cycle_index,
            project_code=request.project_code,
            is_active=existing_project.is_active,
            target_assignee_type=existing_project.target_assignee_type,
            additional_sites=existing_project.additional_sites,
            excluded_sites=existing_project.excluded_sites,
            scope_doc_id=existing_project.scope_doc_id,
            scope_doc_name=existing_project.scope_doc_name,
            project_type=existing_project.project_type,
        )

        # Create ProjectMaster instance
        project: ProjectMaster = ProjectMaster.model_construct(
            **new_project_data.__dict__
        )

        created_project = self.create(project)

        # Clone project fields
        self._clone_project_fields(request.existing_project_id, created_project.id)
        logger.info(
            f"Successfully cloned project '{request.existing_project_id}' to new project '{created_project.id}' "
            f"with code '{request.project_code}'"
        )

        return created_project

    def _clone_project_fields(self, source_project_id: UUID, target_project_id: UUID):
        """Clone project fields from source project to target project."""
        try:
            # Get existing project fields
            existing_project_fields = self._project_field_service.get_by_project_id(
                source_project_id
            )

            if existing_project_fields:
                # Create updates for the new project by copying and updating project_id
                project_field_updates = []
                for field in existing_project_fields:
                    # Create a new field definition for the target project
                    field_update = ProjectFieldDefinitionUpdate(
                        lookup_group_id=field.lookup_group_id,
                        name=field.name,
                        dependent_on=field.dependent_on,
                        visibility_expression=field.visibility_expression,
                        display_name=field.display_name,
                        description=field.description,
                        data_type=field.data_type,
                        data_options=field.data_options,
                        dependency_condition=field.dependency_condition,
                        sequence=field.sequence,
                        is_required=field.is_required,
                        is_track_time=field.is_track_time,
                        hyperlink_url=field.hyperlink_url,
                    )
                    project_field_updates.append(field_update)

                # Set the project fields for the new project
                self._project_field_service.set_project_fields(
                    target_project_id, project_field_updates
                )
        except Exception as e:
            logger.error(
                f"Failed to clone project fields from {source_project_id} to {target_project_id}: {str(e)}"
            )
            raise ValidationFailedException(detail="Failed to clone project fields")

    def _ensure_unique_project_code(self, id: UUID, item: ProjectMaster):
        """
        Checks if the Project Code provided to the Project is unique. Raises
        validation failed exception if the Project Code is not unique.
        """

        # Convert the input username to lowercase
        existing_project_code = self._project2_repository.get_by_project_code(
            item.project_code
        )
        if existing_project_code and existing_project_code.id != id:
            raise ValidationFailedException(
                detail=f"Another project with project code '{existing_project_code.project_code}' already exists."
            )

    def _ensure_unique_project_code_for_cloned_project(self, project_code: str):
        """
        Checks if the Project Code provided to the Project is unique. Raises
        validation failed exception if the Project Code is not unique.
        """
        existing_project = self._project2_repository.get_by_project_code(project_code)

        if existing_project:
            raise ValidationFailedException(
                detail=f"Another project with project code '{project_code}' already exists."
            )

    def _ensure_valid_project_name(self, name: str):
        """
        Validates that the project name contains only alphabetic characters and underscores,
        and does not contain spaces or other special characters.
        """
        if " " in name or not all(char.isalnum() or char == "_" for char in name):
            raise ValidationFailedException(
                detail="Project name must contain only alphabetic characters and underscores, with no spaces or other special characters."
            )

    def _ensure_valid_project_type(self, project_type: Optional[str]):
        """
        Validates that the project type is not None.
        """
        if project_type is None:
            raise ValidationFailedException(detail="Project type is required.")

    def upload_file_for_project_scope(
        self,
        file: UploadFile = File(...),
        sheet_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Uploads an Excel file for project scope, stores metadata and content,
        extracts site names from the first column, and returns them as a comma-separated string.
        """

        # Validate file name length
        if len(file.filename) > 50:
            raise ValidationFailedException(
                detail="File name cannot exceed 50 characters."
            )

        # Validate sheet name length
        if sheet_name and len(sheet_name) > 50:
            raise ValidationFailedException(
                detail="Sheet name cannot exceed 50 characters."
            )

        if self._user_repository.get_storage_type() == AZURE_BLOB:

            document = self._document_store_service.upload_documents(
                file=file,
                doc_type="project_scope",
                purpose="Project Scope Document",
                status="Temporary",
                sheet_name=sheet_name,
            )

            t_path = self._document_store_service.get_by_id(document.id)
            doc_id = document.id
            site_names = self._document_store_service.read_excel_from_azure(
                blob_path=t_path.file_path, sheet_name=sheet_name
            )

        else:
            # Save file temporarily
            temp_file_path = os.path.join(UPLOAD_DIRECTORY, file.filename)
            with open(temp_file_path, "wb") as temp_file:
                temp_file.write(file.file.read())

            site_names = self.extract_sites_from_file_content(
                temp_file_path, sheet_name
            )

            # Step 2: Create and save document metadata
            doc_metadata = DocumentStoreCreate(
                name=file.filename,
                author=self._current_user_provider.user_name,
                doc_type="project_scope",
                storage_type="filesystem",
                sheet_name=sheet_name,
                purpose="Project Scope Document",
                status="Temporary",
            )
            saved_metadata = self._document_store_service.create(doc_metadata)
            doc_id = saved_metadata.id

            # Step 3: Save file content to document store
            self._document_store_service.save_file_content(doc_id, temp_file_path)

        # Step 4: Validate site names
        validation_result = self._project2_repository.validate_sites_from_input(
            site_names
        )

        # Step 4: Add doc_id to the result and return
        validation_result["doc_id"] = doc_id
        return validation_result

    async def upload_file_for_project_reset(
        self,
        project_id: UUID,
        file: UploadFile,
        sheet_name: Optional[str] = None,
    ) -> ProjectResetValidationResponse:
        self._permission_checker.ensure_permissions(
            any_of_permissions=self._get_permissions_to_modify()
        )
        if len(file.filename) > 200:
            raise ValidationFailedException(
                detail="File name cannot exceed 200 characters."
            )

        # Consistently use upload_documents to support both Azure and FileSystem
        document = self._document_store_service.upload_documents(
            file=file,
            doc_type="project_reset",
            purpose="Project Reset Document",
            status="Temporary",
            sheet_name=sheet_name,
        )
        doc_id = document.id

        # Get file path from document metadata
        t_path = self._document_store_service.get_by_id(doc_id)

        if t_path.storage_type == AZURE_BLOB:
            site_names = self._document_store_service.read_excel_from_azure(
                blob_path=t_path.file_path, sheet_name=sheet_name
            )
        else:
            site_names = self.extract_sites_from_file_content(
                t_path.file_path, sheet_name
            )

        requested_sites = self._normalize_reset_sites(sites=site_names)
        return self._build_project_reset_validation_response(
            project_id=project_id,
            requested_sites=requested_sites,
            file_name=file.filename,
            doc_id=doc_id,
        )

    def validate_project_reset_sites(
        self,
        project_id: UUID,
        request: ProjectResetValidationRequest,
    ) -> ProjectResetValidationResponse:
        self._permission_checker.ensure_permissions(
            any_of_permissions=self._get_permissions_to_reset()
        )

        project = self._project2_repository.get_by_id(project_id)
        self._validate_project_for_reset(project)

        reset_id = request.reset_id
        requested_sites = self._normalize_reset_sites(sites=request.sites)

        if reset_id:
            reset_record = self._project2_repository.get_project_reset_by_id(reset_id)
            if reset_record is None or reset_record.project_id != project_id:
                raise NotFoundException(detail="Project reset request not found.")

            if not requested_sites and reset_record.reset_scope:
                requested_sites = self._normalize_reset_sites(sites=reset_record.reset_scope)

        return self._build_project_reset_validation_response(
            project_id=project_id,
            requested_sites=requested_sites,
            file_name=request.file_name,
            reset_id=reset_id,
        )

    def finalize_project_reset(
        self,
        project_id: UUID,
        request: ProjectResetFinalizeRequest,
    ) -> None:
        self._permission_checker.ensure_permissions(
            any_of_permissions=self._get_permissions_to_reset()
        )
        project = self._get_project_for_reset(project_id)
        self._validate_project_for_reset(project)

        reset_record = self._project2_repository.get_project_reset_by_id(request.reset_id)
        if reset_record is None or reset_record.project_id != project_id:
            raise NotFoundException(detail="Project reset request not found.")
        if reset_record.reset_status == COMPLETED:
            raise ValidationFailedException(
                detail="Selected project reset request is already completed."
            )

        requested_sites = self._normalize_reset_sites(sites=request.sites)
        if not requested_sites and reset_record.reset_scope:
            requested_sites = self._normalize_reset_sites(sites=reset_record.reset_scope)
        if not requested_sites:
            raise ValidationFailedException(
                detail="At least one site is required for project reset."
            )

        validation_result = self._project2_repository.validate_reset_sites_for_project(
            project_id=project_id,
            cycle_index=project.cycle_index,
            input_sites=",".join(requested_sites),
        )
        valid_sites = validation_result.get("valid_sites", [])
        if not valid_sites:
            raise ValidationFailedException(
                detail="No valid project sites were found for the current cycle reset."
            )

        # Batch update status to Pending
        self._project_execution_data_repository.reset_project_execution_sites(
            project_id=project_id,
            cycle_index=project.cycle_index,
            sites=valid_sites,
        )

        # Recalculate recurrence site counts (project master counts are retrieved dynamically via join)
        self._project_recurrence_repository.recalculate_recurrence_site_counts(
            project_id, project.cycle_index
        )

        # Move the reset file to permanent location if it exists
        if reset_record.doc_id:
            document_content = self._document_store_service.get_by_id(
                reset_record.doc_id
            )
            if document_content and document_content.status == "Temporary":
                self._update_document_status(reset_record.doc_id)
                if document_content.storage_type == AZURE_BLOB:
                    destination_path = (
                        f"Project/{project.project_code}/"
                        f"Cycle index - {project.cycle_index}/Reset/"
                        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
                    )
                    self._document_store_service.move_document_to_final_location_in_azure(
                        id=reset_record.doc_id, destination_path=destination_path
                    )

        reset_record.reset_scope = ",".join(valid_sites)
        reset_record.reset_status = COMPLETED
        self._project2_repository.update_project_reset(reset_record)

        return ProjectResetFinalizeResponse(
            message="Project execution data has been reset successfully."
        )

    def _build_project_reset_validation_response(
        self,
        project_id: UUID,
        requested_sites: List[str],
        file_name: Optional[str] = None,
        doc_id: Optional[UUID] = None,
        reset_id: Optional[UUID] = None,
    ) -> ProjectResetValidationResponse:
        project = self._get_project_for_reset(project_id)
        if not requested_sites:
            raise ValidationFailedException(
                detail="At least one site is required for project reset."
            )

        requested_scope = ",".join(requested_sites)

        # Validate sites first to identify valid ones
        validation_result = self._project2_repository.validate_reset_sites_for_project(
            project_id=project_id,
            cycle_index=project.cycle_index,
            input_sites=requested_scope,
        )

        valid_scope = ",".join(validation_result.get("valid_sites", []))

        if reset_id:
            reset_record = self._project2_repository.get_project_reset_by_id(reset_id)
            if not reset_record or reset_record.project_id != project_id:
                raise NotFoundException(detail="Project reset request not found.")
            reset_record.reset_scope = valid_scope
            self._project2_repository.update_project_reset(reset_record)
        else:
            reset_record = self._project2_repository.create_project_reset(
                project_id=project_id,
                reset_scope=valid_scope, # Store only valid sites in reset_scope
                reset_status=PENDING,
                cycle_index=project.cycle_index,
                file_name=file_name,
                doc_id=doc_id,
            )

        return ProjectResetValidationResponse(
            reset_id=reset_record.id,
            project_id=project_id,
            cycle_index=project.cycle_index,
            total_input_sites=validation_result["total_input_sites"],
            len_valid_sites=validation_result["len_valid_sites"],
            invalid_count=validation_result["invalid_count"],
            invalid_sites=validation_result["invalid_sites"],
            duplicate_count=validation_result["duplicate_count"],
            duplicate_sites=validation_result["duplicate_sites"],
            sites_not_in_scope_count=validation_result.get("sites_not_in_scope_count", 0),
            sites_not_in_scope=validation_result.get("sites_not_in_scope", []),
            pending_or_inprogress_count=validation_result.get("pending_or_inprogress_count", 0),
            pending_or_inprogress_sites=validation_result.get("pending_or_inprogress_sites", []),
            valid_sites=validation_result["valid_sites"],
            doc_id=reset_record.doc_id,
            file_name=reset_record.file_name,
        )

    def _get_project_for_reset(self, project_id: UUID) -> ProjectMaster:
        project = self._project2_repository.get_by_id(project_id)
        if not project:
            raise NotFoundException(detail="Project with specified ID not found")
        if project.cycle_index is None:
            raise ValidationFailedException(
                detail="Project cycle is not initialized for reset."
            )
        return project

    def _validate_project_for_reset(self, project: ProjectMaster) -> None:
        """
        Validates if the project is active and within its end date for reset operations.
        """
        if project and (not project.is_active or (project.end_date and project.end_date < datetime.now(timezone.utc))):
            raise ValidationFailedException(
                detail="Inactive project cannot be reset."
            )

    def _normalize_reset_sites(
        self,
        sites: Optional[str] = None,
    ) -> List[str]:
        tokens: List[str] = []
        if sites:
            tokens.extend(re.split(r"[\n\r,]+", sites))

        normalized_sites: List[str] = []
        for token in tokens:
            normalized_site = str(token).strip().upper()
            if normalized_site:
                normalized_sites.append(normalized_site)
        return normalized_sites

    def extract_sites_from_file_content(
        self, file_path: str, sheet_name: str = None
    ) -> str:
        """
        Reads the Excel file and extracts site names from the 'sites' column.
        Raises an exception if the column is not found.
        """

        file_ext = os.path.splitext(file_path)[-1].lower()
        sheet_name = sheet_name or None

        # Validate file extension before attempting to read
        if file_ext not in [".csv", ".xls", ".xlsx"]:
            logger.error("Unsupported file format")
            raise ValidationFailedException(
                detail="Unsupported file format. Please upload a .csv or .xlsx file."
            )

        # try:
        if file_ext == ".csv":
            df = pd.read_csv(file_path)
        else:
            # Check if sheet name exists
            available_sheets = pd.ExcelFile(file_path).sheet_names
            if sheet_name is not None and sheet_name not in available_sheets:
                raise ValidationFailedException(
                    detail=f"Sheet name '{sheet_name}' does not exist in the uploaded file."
                )

            try:

                # Covers both .xls and .xlsx
                df = pd.read_excel(
                    file_path,
                    sheet_name=(sheet_name if sheet_name is not None else 0),
                )

            except Exception as e:
                logger.error(f"Failed to read Excel file: {str(e)}")
                raise BadRequestException(detail=f"Failed to read Excel file")

        if "sites" not in df.columns.str.lower().tolist():
            raise NotFoundException(
                detail="Missing required 'sites' column in the uploaded file."
            )

        # Normalize column names to lowercase for matching
        df.columns = df.columns.str.lower()

        # Extract and clean site names
        sites = df["sites"].dropna().astype(str).str.strip().tolist()

        return ",".join(sites)

    def _update_document_status(self, document_id: UUID) -> None:
        """
        Update the status of a document in the document store.
        """
        document_update = self._document_store_service.get_by_id(document_id)
        if not document_update:
            raise NotFoundException(f"Document with ID {document_id} not found.")

        document_update.status = "Linked"
        self._document_store_service.update(document_id, document_update)

    def delete(self, id: UUID, purge_data: Optional[bool] = False) -> None:
        """
        Delete a project with optional purge of execution data.

        """
        if purge_data:
            self._project_execution_history_repository.move_execution_data_to_history(
                id
            )
            self._project_execution_data_repository.delete_by_project_id(id)
        self._project2_repository.delete(id)

    # def _get_permissions_to_view(self) -> List[str]:
    #     return ["PROJECT.VIEW", "RFT_PROJECT.VIEW"]

    def _get_permissions_to_create(self) -> List[str]:
        return ["PROJECT.ADD", "RFT_PROJECT.ADD"]

    def _get_permissions_to_modify(self) -> List[str]:
        return ["PROJECT.ADD", "PROJECT.MODIFY","RFT_PROJECT.ADD", "RFT_PROJECT.MODIFY"]

    def _get_permissions_to_delete(self) -> List[str]:
        return ["PROJECT.DELETE", "RFT_PROJECT.DELETE"]

    def _get_permissions_to_reset(self) -> List[str]:
        return ["PROJECT.RESET"]
