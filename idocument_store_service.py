from abc import ABC, abstractmethod
from typing import BinaryIO
from uuid import UUID
from modules.document_store.schemas import DocumentCreate, Document
from core.contracts.igeneric_service import IGenericService

class IDocumentStoreService(IGenericService[Document], ABC):

    @abstractmethod
    def save_doc_metadata(self, doc_metadata: DocumentCreate) -> Document:
        pass
    
    @abstractmethod
    def save_file_content(self, doc_id: UUID, file_path: str) -> None:
        pass  
    
    @abstractmethod
    def get_doc_content(self, doc_id: UUID) -> BinaryIO:
        pass
    
    
    