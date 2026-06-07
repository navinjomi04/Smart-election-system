"""Database connection helpers and schema initialization."""

import os
import logging
from contextlib import contextmanager

import mysql.connector
from mysql.connector.errors import ProgrammingError

logger = logging.getLogger(__name__)

def get_db():
    return mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        database=os.environ.get("MYSQL_DATABASE", "voting_system"),
    )


@contextmanager
def db_cursor():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        logger.error(f"Database error in db_cursor: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


@contextmanager
def db_transaction():
    """Single connection with autocommit disabled for atomic multi-statement updates."""
    conn = get_db()
    conn.autocommit = False
    cursor = conn.cursor(dictionary=True)
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        logger.error(f"Database error in db_transaction: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def _count_match(cursor):
    row = cursor.fetchone()
    if not row:
        return False
    val = next(iter(row.values()))
    return int(val) > 0


def _vote_column_exists(cursor, column_name):
    cursor.execute(
        """
        SELECT COUNT(*) AS cnt FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'votes'
          AND COLUMN_NAME = %s
        """,
        (column_name,),
    )
    return _count_match(cursor)


def _user_column_exists(cursor, column_name):
    cursor.execute(
        """
        SELECT COUNT(*) AS cnt FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'users'
          AND COLUMN_NAME = %s
        """,
        (column_name,),
    )
    return _count_match(cursor)


def _ensure_vote_columns(cursor):
    """Idempotent votes column migrations (information_schema + duplicate-column guard)."""
    migrations = [
        ("vote_hash", "ALTER TABLE votes ADD COLUMN vote_hash VARCHAR(255) NULL"),
        ("previous_hash", "ALTER TABLE votes ADD COLUMN previous_hash VARCHAR(255) NULL"),
        ("verification_code", "ALTER TABLE votes ADD COLUMN verification_code VARCHAR(50) NULL"),
    ]
    for col, ddl in migrations:
        if _vote_column_exists(cursor, col):
            continue
        try:
            cursor.execute(ddl)
        except ProgrammingError as err:
            if getattr(err, "errno", None) != 1060:
                raise


def _ensure_user_registered_at(cursor):
    if _user_column_exists(cursor, "registered_at"):
        return
    try:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN registered_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        )
    except ProgrammingError as err:
        if getattr(err, "errno", None) != 1060:
            raise


def init_db():
    with db_cursor() as cursor:
        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS elections (
            id INT AUTO_INCREMENT PRIMARY KEY,
            institution_name VARCHAR(255),
            institution_code VARCHAR(50) UNIQUE,
            start_time DATETIME,
            end_time DATETIME,
            admin_username VARCHAR(100),
            admin_password VARCHAR(255)
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            election_id INT,
            username VARCHAR(100),
            password VARCHAR(255),
            email VARCHAR(255),
            status VARCHAR(20) DEFAULT 'pending',
            has_voted INT DEFAULT 0
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS candidates (
            id INT AUTO_INCREMENT PRIMARY KEY,
            election_id INT,
            name VARCHAR(255)
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS votes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            election_id INT,
            candidate_id INT,
            vote_hash VARCHAR(255),
            previous_hash VARCHAR(255),
            verification_code VARCHAR(50)
        )
        """
        )

        _ensure_vote_columns(cursor)
        _ensure_user_registered_at(cursor)

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            election_id INT,
            type VARCHAR(50),
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
        )
