"""Database handle."""
import sqlalchemy

engine = sqlalchemy.create_engine("postgresql://reports@db/reports")
