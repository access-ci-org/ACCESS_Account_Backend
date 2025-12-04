from sqlmodel import SQLModel, Field
from datetime import datetime, timezone

class OTPEntry(SQLModel, table=True):
    email: str = Field(primary_key=True)
    hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))