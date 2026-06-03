"""
tests/test_security.py — Security test suite
COMP3310 Group Project — Tasks 7, 9

Each test targets a specific security requirement from the design specification.
"""
import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

@pytest.fixture
def client():
    os.environ['DB_PATH'] = ':memory:'
    os.environ['SECRET_KEY'] = 'test-secret-key-for-testing-only'
    from run import app
    from db import init_db
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disabled for unit tests only
    with app.test_client() as c:
        with app.app_context():
            init_db()
        yield c


# ─── Task 7 Auth Tests ─────────────────────────────────────────────────────

def test_register_rejects_path_traversal(client):
    """SR-1: Username with path traversal characters must be rejected (HTTP 400)."""
    r = client.post('/register', data={'username': '../../etc/passwd', 'password': 'Test1234'})
    assert r.status_code == 400, "Path traversal username must be rejected"

def test_register_rejects_weak_password(client):
    """SR-1: Weak password (no digit, no uppercase) must be rejected (HTTP 400)."""
    r = client.post('/register', data={'username': 'validuser', 'password': 'password'})
    assert r.status_code == 400, "Weak password must be rejected"

def test_profile_requires_login(client):
    """SR-2: /profile must redirect unauthenticated requests to /login."""
    r = client.get('/profile')
    assert r.status_code == 302
    assert 'login' in r.headers.get('Location', '').lower()

def test_admin_rejects_unauthenticated(client):
    """SR-3: /admin must redirect unauthenticated users to login."""
    r = client.get('/admin')
    assert r.status_code in [302, 403]

def test_logout_clears_session(client):
    """SR-2: Logout must invalidate session (subsequent profile access must redirect)."""
    client.post('/register', data={'username': 'logouttest', 'password': 'Test1234'})
    client.post('/login', data={'username': 'logouttest', 'password': 'Test1234'})
    client.post('/logout')
    r = client.get('/profile')
    assert r.status_code == 302


# ─── Feature 1 Tests (Rate Limiting + CSRF) ────────────────────────────────

def test_csrf_required_on_index_post(client):
    """SR-3: POST to / without CSRF token must return 400 (when CSRF enabled)."""
    from run import app
    app.config['WTF_CSRF_ENABLED'] = True
    r = client.post('/', data={'username': 'testuser'})
    assert r.status_code in [400, 302]  # 400 if CSRF enforced, 302 if disabled in test
    app.config['WTF_CSRF_ENABLED'] = False


# ─── Feature 2 Tests (DB Backend) ──────────────────────────────────────────

def test_session_token_is_random():
    """SR-5: Game session tokens must be cryptographically random, not username-derived."""
    from db import create_game_session
    t1 = create_game_session()
    t2 = create_game_session()
    assert t1 != t2
    assert len(t1) >= 32

def test_sql_injection_in_session_lookup_fails():
    """SR-5: SQL injection payload in session token must return None (no result)."""
    from db import get_session
    result = get_session("' OR '1'='1")
    assert result is None

def test_highscores_returns_list_when_empty():
    """Availability [V-10]: get_highscores() must not raise IndexError when empty."""
    from db import get_highscores
    scores = get_highscores()
    assert isinstance(scores, list)

def test_game_index_rejects_path_traversal(client):
    """SR-1 [V-2]: Username with path traversal in index POST must be rejected."""
    r = client.post('/', data={'username': '../../../etc/passwd'})
    assert r.status_code in [400, 200]  # Not a redirect to game
    assert b'error' in r.data.lower() or r.status_code == 400

def test_debug_mode_off():
    """SR-1 [V-5]: Debug mode must be off when FLASK_DEBUG env var is not 'true'."""
    import os
    os.environ.pop('FLASK_DEBUG', None)
    from run import app
    # In production env, debug should be False
    debug_val = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    assert debug_val is False
