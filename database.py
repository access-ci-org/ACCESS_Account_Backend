from datetime import datetime, timezone

from sqlmodel import Field, Session, SQLModel, create_engine

from config import DATABASE_URL

engine = create_engine(DATABASE_URL, echo=False)


def init_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    return Session(engine)


class OTPEntry(SQLModel, table=True):
    email: str = Field(primary_key=True)
    hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
