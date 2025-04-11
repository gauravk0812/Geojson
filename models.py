from datetime import datetime
from sqlalchemy.ext.declarative import declarative_base
from core.models.fts_linq_base_model import FtsLinqBaseModel
from helpers.load_config import config
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import MetaData, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
import uuid




class ConfigModel(FtsLinqBaseModel):
    __tablename__ = "config"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    param_name: Mapped[str] = mapped_column(String(30), nullable=False, unique=True)
    param_value: Mapped[str] = mapped_column(String(70), nullable=False)
    param_group: Mapped[str] = mapped_column(String(30), nullable=False, unique=True)


class UserSessionModel(FtsLinqBaseModel):
    __tablename__ = "user_session"

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    refresh_token: Mapped[str] = mapped_column(String)
    logged_in_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    logout_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    client_ip: Mapped[str] = mapped_column(String)
    user_agent: Mapped[str] = mapped_column(String(1024))
    logged_in_through: Mapped[str] = mapped_column(String(20), nullable=False)
