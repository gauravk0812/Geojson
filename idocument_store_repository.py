from abc import ABC, abstractmethod
from core.contracts.igeneric_repository import IGenericRepository
from modules.document_store.schemas import Document, DocumentCreate
from uuid import UUID

class IDocumentStoreRepository(IGenericRepository[Document], ABC): 

    @abstractmethod
    def save_doc_metadata(self, doc_metadata: DocumentCreate) -> Document:
        pass
    
    @abstractmethod
    def save_file_content(self, doc_id: str, file_path: str) -> None:
        pass  
    
    @abstractmethod
    def get_doc_content(self, doc_id: UUID) -> Document:
        pass