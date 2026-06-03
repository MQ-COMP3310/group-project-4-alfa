"""
auth/__init__.py — Authentication module
COMP3310 Group Project — Part 2 (Task 7)

Security controls:
- SECURITY [SR-1]: bcrypt password hashing (cost=12)
- SECURITY [SR-2]: Session-based auth with session fixation prevention
- SECURITY [SR-3]: RBAC — role read from DB on every admin request
- SECURITY [SR-1]: Whitelist input validation
- SECURITY [SR-2]: Account lockout after 5 failed attempts
"""
import sqlite3, re, secrets, os
from functools import wraps
from datetime import datetime, timedelta
from flask import session, redirect, url_for, abort, Blueprint

try:
    import bcrypt
except ImportError:
    raise RuntimeError("Install bcrypt: pip install bcrypt")

DB_PATH = 'data/app.db'
os.makedirs("data", exist_ok=True)  # SECURITY: Ensure data directory exists
auth_bp = Blueprint('auth', __name__)

def get_auth_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_auth_db():
    with get_auth_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user' CHECK(role IN ('user','admin')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_login_count INTEGER DEFAULT 0,
                lockout_until TIMESTAMP,
                share_token TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS game_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                score INTEGER NOT NULL,
                completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

def validate_username(u): return bool(re.match(r'^[a-zA-Z0-9_]{3,30}$', u))
def validate_password(p): return len(p) >= 8 and any(c.isupper() for c in p) and any(c.isdigit() for c in p)
def hash_password(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=12)).decode()
def check_password(p, h): return bcrypt.checkpw(p.encode(), h.encode())

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """SECURITY [SR-3]: Role from DB, not session — prevents cookie forgery for privilege escalation."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        db = get_auth_db()
        user = db.execute('SELECT role FROM users WHERE id=?', (session['user_id'],)).fetchone()
        db.close()
        if not user or user['role'] != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─── Auth Routes ─────────────────────────────────────────────────────────────

from flask import request, render_template, flash

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """SR-1/SR-2: User registration with input validation and bcrypt hashing."""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not validate_username(username):
            return render_template('register.html',
                error='Username must be 3-30 alphanumeric characters or underscores.'), 400
        if not validate_password(password):
            return render_template('register.html',
                error='Password must be 8+ chars with at least one uppercase and one digit.'), 400

        db = get_auth_db()
        existing = db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
        if existing:
            db.close()
            return render_template('register.html', error='Username already taken.'), 409

        pw_hash = hash_password(password)
        share_token = secrets.token_urlsafe(32)
        db.execute(
            'INSERT INTO users (username, password_hash, share_token) VALUES (?, ?, ?)',
            (username, pw_hash, share_token))
        db.commit()
        db.close()
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """SR-2: Login with account lockout after 5 failed attempts."""
    if 'user_id' in session:
        return redirect(url_for('auth.profile'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        db = get_auth_db()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()

        if user:
            # Check lockout
            if user['lockout_until']:
                lockout = datetime.fromisoformat(str(user['lockout_until']))
                if datetime.utcnow() < lockout:
                    db.close()
                    return render_template('login.html',
                        error='Account locked. Try again later.'), 429

            if check_password(password, user['password_hash']):
                # SECURITY [SR-2]: Clear session before login to prevent session fixation
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                # Reset failed count
                db.execute('UPDATE users SET failed_login_count=0, lockout_until=NULL WHERE id=?',
                           (user['id'],))
                db.commit()
                db.close()
                return redirect(url_for('auth.profile'))
            else:
                # Increment failed count
                new_count = (user['failed_login_count'] or 0) + 1
                lockout_until = None
                if new_count >= 5:
                    lockout_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
                db.execute(
                    'UPDATE users SET failed_login_count=?, lockout_until=? WHERE id=?',
                    (new_count, lockout_until, user['id']))
                db.commit()

        db.close()
        return render_template('login.html', error='Invalid username or password.'), 401

    return render_template('login.html')


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """SR-2: Invalidate server-side session on logout."""
    if 'user_id' not in session:
        return redirect(url_for('index')), 403
    session.clear()
    return redirect(url_for('index'))


@auth_bp.route('/profile')
@login_required
def profile():
    """Logged-in user's profile — score history and account info."""
    db = get_auth_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    scores = db.execute(
        'SELECT score, completed_at FROM game_scores WHERE user_id=? ORDER BY completed_at DESC',
        (session['user_id'],)).fetchall()
    db.close()
    return render_template('profile.html', user=user, scores=scores)


@auth_bp.route('/admin')
@admin_required
def admin():
    """Admin dashboard — view all users and scores."""
    db = get_auth_db()
    users = db.execute('SELECT id, username, role, created_at FROM users ORDER BY id').fetchall()
    scores = db.execute(
        'SELECT game_scores.id, users.username, game_scores.score, game_scores.completed_at '
        'FROM game_scores JOIN users ON users.id=game_scores.user_id ORDER BY completed_at DESC'
    ).fetchall()
    db.close()
    return render_template('admin.html', users=users, scores=scores)


@auth_bp.route('/admin/scores/<int:score_id>', methods=['POST'])
@admin_required
def delete_score(score_id):
    """Admin: Delete a score record. CSRF protected."""
    db = get_auth_db()
    row = db.execute('SELECT id FROM game_scores WHERE id=?', (score_id,)).fetchone()
    if not row:
        db.close()
        return 'Score not found', 404
    db.execute('DELETE FROM game_scores WHERE id=?', (score_id,))
    db.commit()
    db.close()
    return redirect(url_for('auth.admin'))


@auth_bp.route('/admin/users/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Admin: Delete a user and cascade-delete their scores. CSRF protected."""
    db = get_auth_db()
    row = db.execute('SELECT id FROM users WHERE id=?', (user_id,)).fetchone()
    if not row:
        db.close()
        return 'User not found', 404
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    db.close()
    return redirect(url_for('auth.admin'))
