"""
db.py — Secure SQLite Database Backend
COMP3310 Group Project — Feature 2

Replaces flat-file storage with parameterised SQLite queries.
SECURITY [V-2]: Eliminates path traversal — no file paths derived from user input.
SECURITY [SQL-INJECTION]: All queries use parameterised statements (? placeholders).
"""

import sqlite3
import secrets
import os
from contextlib import contextmanager

DB_PATH = os.environ.get('DB_PATH', 'data/game.db')
os.makedirs("data", exist_ok=True)  # SECURITY: Ensure data directory exists at startup


@contextmanager
def get_db():
    """Context manager for database connections — auto-commit and close."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # SECURITY: Enforce FK constraints
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables. Idempotent (IF NOT EXISTS)."""
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS riddles (
                id INTEGER PRIMARY KEY,
                question TEXT NOT NULL,
                answer TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS game_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                riddle_index INTEGER DEFAULT 0,
                score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS guesses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES game_sessions(id) ON DELETE CASCADE,
                riddle_id INTEGER NOT NULL,
                guess_text TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS highscores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                final_score INTEGER NOT NULL,
                completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Seed riddles if empty
        count = db.execute('SELECT COUNT(*) FROM riddles').fetchone()[0]
        if count == 0:
            _seed_riddles(db)


def _seed_riddles(db):
    riddles = [
        ("It is greater than God and more evil than the devil. The poor have it, the rich need it and if you eat it you'll die. What is it?", "Nothing"),
        ("What always runs but never walks, often murmurs, never talks, has a bed but never sleeps, has a mouth but never eats?", "River"),
        ("The more you have of it, the less you see. What is it?", "Darkness"),
        ("What English word has three consecutive double letters?", "Bookkeeper"),
        ("What's black when you get it, red when you use it, and white when you're all through with it?", "Charcoal"),
        ("All about, but cannot be seen, Can be captured, cannot be held, No throat, but can be heard.", "Wind"),
        ("Until I am measured I am not known, Yet how you miss me when I have flown.", "Time"),
        ("When set loose, I fly away, Never so cursed as when I go astray.", "Fart"),
        ("Lighter than what I am made of, More of me is hidden Than is seen.", "Iceberg"),
        ("Three lives have I. Gentle enough to soothe the skin, Light enough to caress the sky, Hard enough to crack rocks.", "Water"),
    ]
    db.executemany(
        'INSERT INTO riddles (question, answer) VALUES (?, ?)', riddles)


def get_riddles():
    """Return all riddles ordered by ID."""
    with get_db() as db:
        return db.execute('SELECT id, question, answer FROM riddles ORDER BY id').fetchall()


def create_game_session() -> str:
    """
    SECURITY: Session token is cryptographically random.
    Never derived from username — eliminates IDOR and path traversal.
    """
    token = secrets.token_urlsafe(32)
    with get_db() as db:
        db.execute(
            'INSERT INTO game_sessions (session_token) VALUES (?)', (token,))
    return token


def get_session(token: str):
    """SECURITY: Parameterised lookup — SQL injection impossible."""
    with get_db() as db:
        return db.execute(
            'SELECT * FROM game_sessions WHERE session_token = ?', (token,)).fetchone()


def record_guess(session_id: int, riddle_id: int, guess: str):
    """Store a guess. SECURITY: guess stored in DB, not in user-path file."""
    with get_db() as db:
        db.execute(
            'INSERT INTO guesses (session_id, riddle_id, guess_text) VALUES (?, ?, ?)',
            (session_id, riddle_id, guess))


def get_guess_count(session_id: int, riddle_id: int) -> int:
    """
    SECURITY: Guess count derived from DB — cannot be manipulated by client.
    Replaces len(file.readlines()) which was writable via file path.
    """
    with get_db() as db:
        row = db.execute(
            'SELECT COUNT(*) AS cnt FROM guesses WHERE session_id=? AND riddle_id=?',
            (session_id, riddle_id)).fetchone()
    return row['cnt'] if row else 0


def add_score(session_id: int, points: int):
    """Atomically add points to session score."""
    with get_db() as db:
        db.execute(
            'UPDATE game_sessions SET score = score + ? WHERE id = ?', (points, session_id))


def advance_riddle(session_id: int):
    """Advance riddle_index by 1 server-side — SECURITY: client cannot skip riddles."""
    with get_db() as db:
        db.execute(
            'UPDATE game_sessions SET riddle_index = riddle_index + 1 WHERE id = ?',
            (session_id,))


def get_session_score(session_id: int) -> int:
    """Return current score for a session."""
    with get_db() as db:
        row = db.execute(
            'SELECT score FROM game_sessions WHERE id = ?', (session_id,)).fetchone()
    return row['score'] if row else 0


def save_highscore(username: str, final_score: int):
    """SECURITY: Username validated at input boundary before reaching this function."""
    with get_db() as db:
        db.execute(
            'INSERT INTO highscores (username, final_score) VALUES (?, ?)',
            (username, final_score))


def get_highscores(limit: int = 10):
    """
    SECURITY [V-10]: LIMIT clause prevents IndexError on highscores page.
    Returns at most `limit` records regardless of DB contents.
    """
    assert isinstance(limit, int) and 0 < limit <= 100, "Invalid limit"
    with get_db() as db:
        rows = db.execute(
            'SELECT username, final_score FROM highscores ORDER BY final_score DESC LIMIT ?',
            (limit,)).fetchall()
    # Return as list of tuples for template compatibility
    return [(r['username'], str(r['final_score'])) for r in rows]
