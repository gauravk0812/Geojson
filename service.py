import os
from pathlib import Path
import shutil
from typing import BinaryIO
from uuid import UUID, uuid4

from injector import inject
from fastapi_injector import Injected

from core.contracts.ipermission_checker import IPermissionChecker
from modules.document_store.idocument_store_service import IDocumentStoreService
from modules.document_store.idocument_store_repository import IDocumentStoreRepository

from app_settings import AppSettings
from modules.document_store.schemas import DocumentCreate, Document

from core.contracts.idatetime_provider import IDateTimeProvider
from core.generic_service import GenericService

from helpers.log import get_logger
logger = get_logger(__name__)

config = AppSettings()

BASE_DOC_STORE_DIRECTORY = Path(config.BASE_DOC_STORE_DIRECTORY)
BASE_DOC_STORE_DIRECTORY.mkdir(exist_ok=True)
        
class DocumentStoreService(IDocumentStoreService, GenericService[Document]):
    """
    Document store service implements the business logic layer for document store module.
    It is responsible for access control and business rules validations.
    It does not interact with the database directly. It uses the
    document store repository for that purpose.
    """
    @inject
    def __init__(self, 
                repository: IDocumentStoreRepository = Injected(IDocumentStoreRepository),
                date_time_provider: IDateTimeProvider = Injected(IDateTimeProvider),
                permission_checker: IPermissionChecker = Injected(IPermissionChecker),
                ) -> None:

        super().__init__(Document, repository, permission_checker)
        self._doc_store_repository : IDocumentStoreRepository = repository
        self._current_date_provider : IDateTimeProvider = date_time_provider

    def save_doc_metadata(self, doc_metadata: DocumentCreate) -> Document:
        doc_id = uuid4()
        doc_metadata = doc_metadata.dict()
        doc_metadata["id"] = doc_id
        return self._doc_store_repository.save_doc_metadata(doc_metadata)

    def save_file_content(self, doc_id: UUID, file_path: str) -> None:
        """
        Saves the metadata of a document object.

        Args:
            db (Session): The database session.
            doc_id (UUID): The document ID.
            file_path (str): The path of the file to be moved.

        Returns:
            None
        """
        try:
            # Fetch the document metadata to get the doc_type
            doc_metadata = self._doc_store_repository.get_doc_content(doc_id)
            if not doc_metadata:
                raise ValueError(f"Document with ID {doc_id} not found.")
            
            # Extract doc_type from the metadata
            doc_type = doc_metadata.doc_type 

            # Construct the final file path
            current_date = self._current_date_provider.get_current_utc_date_time()
            year = current_date.year
            month = f"{current_date.month:02}" 

            #document types
            folder_path = os.path.join(BASE_DOC_STORE_DIRECTORY, doc_type, str(year), month)

            # Create the folder if it doesn't exist
            os.makedirs(folder_path, exist_ok=True)

            # Extract the original file extension
            _, file_extension = os.path.splitext(file_path)
            if not file_extension:
                raise ValueError("File format is missing from the provided file path.")

            # Sanitize and move the file to the final destination
            sanitized_filename = f"{os.path.basename(file_path)}_{doc_id}{file_extension}"

            final_file_path = os.path.join(folder_path, sanitized_filename)

            # Move the file to the final destination
            shutil.move(file_path, final_file_path)

            # Update document store with the final file path
            self._doc_store_repository.save_file_content(doc_id, os.path.abspath(final_file_path))
        except Exception as e:
            logger.error(f"Failed to save file content: {e}")
            raise

    def get_doc_content(self, doc_id: UUID) -> BinaryIO:
        """
        Retrieves the document content as a binary stream by document ID.
        """
        # Fetch document details (including file path) from the database
        doc = self._doc_store_repository.get_doc_content(doc_id)
        if not doc:
            raise FileNotFoundError(f"Document with ID {doc_id} not found.")
       
        # Open and return the file stream
        return open(doc.file_path, 'rb')