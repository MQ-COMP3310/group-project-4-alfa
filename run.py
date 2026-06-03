"""
run.py — Riddle Me This (Secure Implementation)
COMP3310 Group Project — S1 2026

Security improvements applied:
- SECURITY [V-1]: Removed global username variable; replaced with server-side Flask sessions
- SECURITY [V-3]: Secret key loaded from environment variable (never hardcoded)
- SECURITY [V-4]: CSRF protection via Flask-WTF
- SECURITY [V-5]: Debug mode controlled via environment variable
- SECURITY [V-2]: All file operations replaced with parameterised SQLite queries (see db.py)
- SECURITY [V-9]: Removed Python 2 reload(sys) pattern
"""

import os
import secrets
from flask import Flask, render_template, redirect, request, url_for, session
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from db import init_db, create_game_session, get_session, record_guess, get_guess_count, \
               add_score, save_highscore, get_highscores, get_session_score, get_riddles
from auth import auth_bp, login_required, admin_required, init_auth_db

app = Flask(__name__, template_folder='Templates')

# SECURITY [V-3]: Secret key from environment variable, never hardcoded
# Run: export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# SECURITY [V-4]: Enable CSRF protection globally on all POST forms
csrf = CSRFProtect(app)

# SECURITY [T-4]: Rate limiting to prevent denial-of-service via file/resource exhaustion
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# SECURITY: Session cookie hardening
app.config['SESSION_COOKIE_HTTPONLY'] = True   # Prevent JS access to cookie
app.config['SESSION_COOKIE_SECURE'] = True     # HTTPS only
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF mitigation
app.config['PERMANENT_SESSION_LIFETIME'] = 1800    # 30 minute session expiry

# Register authentication blueprint
app.register_blueprint(auth_bp)

# Initialise database on startup
with app.app_context():
    init_db()
    init_auth_db()  # SECURITY: Initialise user/auth tables


# HOMEPAGE
@app.route('/', methods=["GET", "POST"])
@limiter.limit("20 per minute")  # SECURITY [T-4]: Rate limit to prevent file exhaustion
def index():
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        # SECURITY [V-2]: Input validation — whitelist only safe characters
        import re
        if not username or not re.match(r'^[a-zA-Z0-9_]{1,30}$', username):
            return render_template("index.html", page_title="Home",
                                   error="Username must be 1-30 alphanumeric characters or underscores.")
        return redirect(url_for('user', username=username))
    return render_template("index.html", page_title="Home")


# USER WELCOME PAGE
@app.route('/<username>', methods=["GET", "POST"])
def user(username):
    # SECURITY [V-2]: Validate username before any use
    import re
    if not re.match(r'^[a-zA-Z0-9_]{1,30}$', username):
        return redirect(url_for('index'))

    if request.method == "POST":
        # SECURITY [V-1]: Create game session (server-side token, not file based on username)
        session_token = create_game_session()
        session['game_token'] = session_token
        session['game_username'] = username
        return redirect(url_for('game', username=username))

    return render_template("welcome.html", username=username)


# GAME PAGE
@app.route('/<username>/game', methods=["GET", "POST"])
@limiter.limit("30 per minute")  # SECURITY [T-4]: Prevent automated answer submission
def game(username):
    # SECURITY [V-1]: Game state retrieved from server-side session, not global variable
    game_token = session.get('game_token')
    if not game_token:
        return redirect(url_for('user', username=username))

    game_sess = get_session(game_token)
    if not game_sess:
        return redirect(url_for('user', username=username))

    riddles = get_riddles()
    riddle_index = game_sess['riddle_index']

    if request.method == "POST":
        # SECURITY [T-2]: riddle_index sourced from SERVER (database), not client form field
        # The client cannot manipulate game progression
        user_response = request.form.get("answer", "").strip().title()

        # SECURITY [V-2]: Record guess in DB (not a file with user-controlled path)
        record_guess(game_sess['id'], riddle_index, user_response)
        guess_count = get_guess_count(game_sess['id'], riddle_index)

        correct_answer = riddles[riddle_index]['answer']

        if correct_answer == user_response:
            points = max(1, 4 - guess_count)
            add_score(game_sess['id'], points)

            if riddle_index < len(riddles) - 1:
                # Advance to next riddle (server updates DB)
                from db import advance_riddle
                advance_riddle(game_sess['id'])
            else:
                # Game complete
                final = get_session_score(game_sess['id'])
                save_highscore(session.get('game_username', username), final)
                return redirect(url_for('congrats', username=username))
        else:
            if guess_count >= 3:
                return redirect(url_for('gameover', username=username))

        # Refresh session data
        game_sess = get_session(game_token)
        riddle_index = game_sess['riddle_index']

    guesses = []  # Retrieved from DB for display
    remaining = max(0, 3 - get_guess_count(game_sess['id'], riddle_index))
    score = get_session_score(game_sess['id'])

    return render_template("game.html",
                           username=username,
                           riddle_index=riddle_index,
                           riddles=[r['question'] for r in riddles],
                           attempts=guesses,
                           remaining_attempts=remaining,
                           score=score)


# GAMEOVER PAGE
@app.route('/<username>/gameover', methods=["GET", "POST"])
def gameover(username):
    session.pop('game_token', None)  # Clear game session

    if request.method == "POST":
        return redirect(url_for('user', username=username))

    return render_template("gameover.html", username=username)


# FINISH PAGE
@app.route('/<username>/congratulations', methods=["GET", "POST"])
def congrats(username):
    score = request.args.get('score', 0)
    if request.method == "POST":
        return redirect(url_for('highscores'))
    return render_template("congratulations.html", username=username, score=score)


# HIGHSCORE PAGE
@app.route('/highscores')
@limiter.limit("60 per minute")
def highscores():
    # SECURITY [V-10]: get_highscores uses LIMIT 10 — no IndexError possible
    usernames_and_scores = get_highscores(limit=10)
    return render_template("highscores.html", page_title="Highscores",
                           usernames_and_scores=usernames_and_scores)


if __name__ == '__main__':
    ip = "127.0.0.1"
    port = 8000
    # SECURITY [V-5]: Debug mode OFF in production; controlled by environment variable
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host=ip, port=port, debug=debug_mode)
