from sqlalchemy import func
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from fastapi_injector import Injected
from injector import inject
from uuid import UUID

from modules.document_store.models import DocumentModel
from modules.document_store.schemas import DocumentCreate, Document
from modules.document_store.idocument_store_repository import IDocumentStoreRepository

from core.contracts.icurrent_user_provider import ICurrentUserProvider
from core.contracts.idatetime_provider import IDateTimeProvider
from core.generic_sql_repository import GenericSqlRepository

from helpers.log import get_logger

logger = get_logger(__name__)  

class DocumentStoreRepository(IDocumentStoreRepository, GenericSqlRepository[Document]):
    """
    Document Store repository implements the persistence layer for Document store module.
    It is responsible for fetching and persisting documents.
    It does not interact with the database directly. It uses the
    daDocument stroe repository for that purpose.
    """ 
    @inject
    def __init__(self, 
                 session: Session = Injected(Session),
                 current_user_provider: ICurrentUserProvider = Injected(ICurrentUserProvider),
                 date_time_provider: IDateTimeProvider = Injected(IDateTimeProvider),
                 ) -> None:
        
        super().__init__(
                        logger=logger,
                        session=session, 
                        current_user_provider=current_user_provider,
                        date_time_provider=date_time_provider,
                        item_schema=Document, 
                        item_db_model=DocumentModel)   
      
    def save_doc_metadata(self, doc_metadata: DocumentCreate) -> Document:
        """
        Saves document metadata into the database.

        Args:
            db (sqlalchemy.orm.Session): The database session for saving metadata.
            doc_metadata (DocumentCreate): The metadata to save.

        Returns:
            Document: The saved document instance.
        """
        doc = DocumentModel(**doc_metadata)
        doc = self._preprocess_resource(doc, b_adding=True)

        self._db_session.add(doc)
        self._db_session.commit()
        self._db_session.refresh(doc)
        return doc

    def save_file_content(self, doc_id: UUID, file_path: str) -> None:
        """
        Saves the file content path for the given document.

        Args:
            db (sqlalchemy.orm.Session): The database session for saving the file path.
            doc_id (UUID): The unique identifier of the document.
            file_path (str): The path where the file is stored.
        """
        doc = self._db_session.query(DocumentModel).filter(DocumentModel.id == doc_id).first()
        if doc:
            # Store the file content, e.g., move the file to the appropriate storage
            doc.file_path = file_path

            # Preprocess the document before saving
            doc = self._preprocess_resource(doc, b_adding=False)
            self._db_session.commit()
            self._db_session.refresh(doc)

    
    def get_doc_content(self, doc_id: UUID) -> Document:
        """
        Retrieves the metadata of a file for a given document.
 
        Args:
            db (sqlalchemy.orm.Session): The database session for querying the document.
            doc_id (UUID): The unique identifier of the document.
 
        Returns:
            Documnet: The document record containing metadata (e.g., file path).
        """
        return self._db_session.query(DocumentModel).filter(DocumentModel.id == doc_id).first()
 
