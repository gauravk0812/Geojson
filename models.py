import uuid
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from core.models.petal_base_model import PetalBaseModel
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class DocumentModel(PetalBaseModel):
    """
    Represents a model for storing document-related metadata and information in the database.
    Inherits from the custom `PetalBaseModel` which provides additional functionality.
    """
    __tablename__ = "document_store"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)  
    author: Mapped[str] = mapped_column(String(255), nullable=True)  
    doc_type: Mapped[str] = mapped_column(String(50), nullable=True) 
    file_path: Mapped[str] = mapped_column(String(255), nullable=True)  
    storage_type: Mapped[str] = mapped_column(String(50), default="filesystem")

