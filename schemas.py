from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from core.schemas.fts_linq_base_schemas import FtsLinqBaseSchema
from modules.user.schemas import User
from uuid import UUID


class AuthenticationResponse(BaseModel):
    user: User
    access_token: str
    session_id: UUID
    refresh_token: str
    expires_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class Config(FtsLinqBaseSchema):
    # id: UUID
    param_name: str
    param_value: str
    param_group: str

    class Config:
        from_attributes = True
