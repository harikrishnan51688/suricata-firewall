from sqlalchemy import (create_engine, Column, Integer, BigInteger, Text, TIMESTAMP,
                        Boolean, JSON, ForeignKey, func, select, and_, Index)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import IntegrityError
import os
import psycopg2
from psycopg2 import OperationalError

DB_NAME = "ruleset"
DB_USER = "postgres"
DB_PASSWORD = "postgres"
DB_HOST = "localhost"
DB_PORT = 5432

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/ruleset')

# ---------- DB setup ----------
engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


# ---------- Models (matching user's schema) ----------
class Feed(Base):
    __tablename__ = 'feeds'
    id = Column(Integer, primary_key=True)
    name = Column(Text, unique=True, nullable=False)
    url = Column(Text)
    type = Column(Text) # 'snort','suricata','git','raw'
    trust_level = Column(Integer, default=50)
    last_fetched_at = Column(TIMESTAMP)

    rules = relationship('Rule', back_populates='feed')


class Rule(Base):
    __tablename__ = 'rules'
    id = Column(Integer, primary_key=True)
    sid = Column(BigInteger, index=True)
    rev = Column(Integer)
    engine_type = Column(Text)
    source_feed_id = Column(Integer, ForeignKey('feeds.id'))
    category = Column(Text)
    severity = Column(Text)
    raw_text = Column(Text)
    parsed = Column(JSON)
    first_seen = Column(TIMESTAMP, server_default=func.now())
    last_seen = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    is_valid = Column(Boolean, default=None)

    feed = relationship('Feed', back_populates='rules')


class Ruleset(Base):
    __tablename__ = 'rulesets'
    id = Column(Text, primary_key=True)
    profile = Column(Text)
    engine_type = Column(Text)
    created_at = Column(TIMESTAMP, server_default=func.now())
    file_path = Column(Text)
    changelog = Column(Text)


class Firewall(Base):
    __tablename__ = 'firewalls'
    id = Column(Integer, primary_key=True)
    name = Column(Text)
    device_token = Column(Text, unique=True)
    profile = Column(Text)
    current_ruleset_id = Column(Text, ForeignKey('rulesets.id'))
    last_checked = Column(TIMESTAMP)



def create_database_if_not_exists():
    """
    Connects to the default 'postgres' database and creates the target database
    if it does not already exist.
    """
    # Create a new connection URL that points to the administrative 'postgres' database
    admin_url = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/postgres"
    
    conn = None
    try:
        # Connect to the administrative 'postgres' database
        conn = psycopg2.connect(admin_url)
        # CREATE DATABASE cannot run inside a transaction block, so autocommit is required
        conn.autocommit = True
        cursor = conn.cursor()

        # Check if the database exists
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname='{DB_NAME}'")
        exists = cursor.fetchone()

        if not exists:
            print(f"Database '{DB_NAME}' not found. Creating it now...")
            # Execute the CREATE DATABASE command
            cursor.execute(f"CREATE DATABASE {DB_NAME}")
            print(f"Database '{DB_NAME}' created successfully.")
        else:
            print(f"Database '{DB_NAME}' already exists.")

    except OperationalError as e:
        print(f"❌ FATAL ERROR: Could not connect to the PostgreSQL server (Host/Port/Credentials).")
        print(f"Please check your DATABASE_URL: {DATABASE_URL}")
        print(f"Error details: {e}")
        raise
    
    finally:
        if conn:
            conn.close()



# Create tables (first-run)
def init_db():
    create_database_if_not_exists()
    Base.metadata.create_all(engine)



if __name__ == '__main__':
    init_db()