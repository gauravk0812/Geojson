from pydantic import BaseModel
from core.schemas.petal_base_schemas import PetalBaseSchema

# Base schema for a Document
class DocumentBase(BaseModel):
    name: str
    author: str
    doc_type: str
    storage_type: str

# Schema for creating a Document (inherits from Document)
class DocumentCreate(DocumentBase):
    pass

# Schema for updating a Document (inherits from Document)
class DocumentUpdate(DocumentBase):
    pass

# Final Document model, which also inherits from PetalBaseSchema
class Document(DocumentBase, PetalBaseSchema): 
    class Config:
        from_attributes = True