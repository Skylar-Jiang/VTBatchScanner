from collections.abc import Callable
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


SessionFactory = Callable[[], Session]


def create_session_factory(database_url: str) -> SessionFactory:
    import app.models  # Ensure every model is registered before create_all.

    parsed_url = make_url(database_url)
    if parsed_url.drivername.startswith("sqlite") and parsed_url.database not in {None, ":memory:"}:
        Path(parsed_url.database).parent.mkdir(parents=True, exist_ok=True)
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
