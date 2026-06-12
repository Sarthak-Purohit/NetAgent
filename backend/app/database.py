from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite:///./netagent.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 30
    }
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

_SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class SessionLocalProxy:
    def __init__(self):
        self._override = None

    def set_override(self, sessionmaker_instance):
        self._override = sessionmaker_instance

    def __call__(self, *args, **kwargs):
        if self._override is not None:
            return self._override(*args, **kwargs)
        return _SessionLocal(*args, **kwargs)

    def __getattr__(self, name):
        if self._override is not None:
            return getattr(self._override, name)
        return getattr(_SessionLocal, name)

SessionLocal = SessionLocalProxy()
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
