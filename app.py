"""URL Shortener - Flask + SQLite.

Features: URL shortening, custom aliases, expiry, redirect engine with cache,
click analytics, user auth (sign-up/login), link dashboard API, IP rate limiting.
"""
import os
import re
import secrets
import sqlite3
import string
import time
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, g, jsonify, redirect, request, send_from_directory
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data.db"))
SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
PORT = int(os.environ.get("PORT", 3000))
RESERVED = {"api", "index.html", "favicon.ico"}
ALPHABET = string.ascii_letters + string.digits

app = Flask(__name__, static_folder=None)
tokens = URLSafeTimedSerializer(SECRET)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, url TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id), expires_at INTEGER, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY, link_id INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL, referrer TEXT, country TEXT, ua TEXT);
CREATE INDEX IF NOT EXISTS idx_clicks_link ON clicks(link_id, ts);
"""


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


with sqlite3.connect(DB_PATH) as _c:
    _c.executescript(SCHEMA)


# ---------- helpers ----------
def now_ms():
    return int(time.time() * 1000)


def err(msg, code):
    return jsonify(error=msg), code


def gen_code(n=7):
    return "".join(secrets.choice(ALPHABET) for _ in range(n))


def fmt(row, **extra):
    d = dict(row)
    d["shortUrl"] = f"{request.host_url}{d['code']}"
    d.update(extra)
    return d


# tiny LRU cache for short->long lookups (swap for Redis in production)
CACHE, CACHE_MAX = OrderedDict(), 1000


def cache_get(code):
    if code in CACHE:
        CACHE.move_to_end(code)
        return CACHE[code]


def cache_set(code, val):
    CACHE[code] = val
    if len(CACHE) > CACHE_MAX:
        CACHE.popitem(last=False)


# in-memory per-IP rate limiter
HITS = defaultdict(deque)


def rate_limit(name, limit, window):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            q, t = HITS[(name, request.remote_addr)], time.time()
            while q and q[0] < t - window:
                q.popleft()
            if len(q) >= limit:
                return err("Too many requests, slow down", 429)
            q.append(t)
            return fn(*a, **kw)
        return wrapper
    return deco


def current_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        return tokens.loads(token, max_age=7 * 86400)
    except (BadSignature, Exception):
        return None


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        g.user = current_user()
        if not g.user:
            return err("Unauthorized", 401)
        return fn(*a, **kw)
    return wrapper


def make_token(user_id, email):
    return tokens.dumps({"id": user_id, "email": email})


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp


# ---------- pages ----------
@app.get("/")
def home():
    return send_from_directory(os.path.join(BASE_DIR, "static"), "index.html")


# ---------- auth ----------
@app.post("/api/v1/auth/register")
@rate_limit("auth", 20, 900)
def register():
    d = request.get_json(silent=True) or {}
    email, pw = (d.get("email") or "").strip().lower(), d.get("password") or ""
    if not re.fullmatch(r"\S+@\S+\.\S+", email) or len(pw) < 8:
        return err("Valid email and 8+ char password required", 400)
    try:
        first = db().execute("SELECT COUNT(*) n FROM users").fetchone()["n"] == 0  # first user = admin
        cur = db().execute("INSERT INTO users (email, hash, is_admin) VALUES (?, ?, ?)",
                           (email, generate_password_hash(pw), int(first)))
        db().commit()
    except sqlite3.IntegrityError:
        return err("Email already registered", 409)
    return jsonify(token=make_token(cur.lastrowid, email)), 201


@app.post("/api/v1/auth/login")
@rate_limit("auth", 20, 900)
def login():
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    u = db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not u or not check_password_hash(u["hash"], d.get("password") or ""):
        return err("Invalid credentials", 401)
    return jsonify(token=make_token(u["id"], u["email"]))


# ---------- links ----------
@app.post("/api/v1/links")
@rate_limit("api", 60, 60)
def create_link():
    user = current_user()
    d = request.get_json(silent=True) or {}
    url = (d.get("url") or "").strip()
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        return err("A valid http(s) URL is required", 400)
    if p.netloc == request.host:
        return err("Cannot shorten links to this service", 400)

    alias = (d.get("alias") or "").strip()
    if alias and (not re.fullmatch(r"[\w-]{3,32}", alias) or alias.lower() in RESERVED):
        return err("Alias must be 3-32 chars (letters, numbers, - _)", 400)

    exp = None
    if d.get("expiresAt"):
        try:
            dt = datetime.fromisoformat(str(d["expiresAt"]).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            exp = int(dt.timestamp() * 1000)
        except ValueError:
            return err("Invalid expiresAt", 400)
        if exp < now_ms():
            return err("expiresAt must be a future date", 400)

    if user and not alias and not exp:  # same user + same URL -> reuse existing short link
        dup = db().execute("SELECT * FROM links WHERE user_id = ? AND url = ? AND expires_at IS NULL "
                           "ORDER BY id LIMIT 1", (user["id"], url)).fetchone()
        if dup:
            return jsonify(fmt(dup)), 200

    for _ in range(5):
        code = alias or gen_code()
        try:
            cur = db().execute(
                "INSERT INTO links (code, url, user_id, expires_at, created_at) VALUES (?,?,?,?,?)",
                (code, url, user["id"] if user else None, exp, now_ms()))
            db().commit()
            row = db().execute("SELECT * FROM links WHERE id = ?", (cur.lastrowid,)).fetchone()
            return jsonify(fmt(row)), 201
        except sqlite3.IntegrityError:
            if alias:
                return err("Alias already taken", 409)
    return err("Could not generate a unique code", 500)


@app.get("/api/v1/links")
@login_required
def list_links():
    rows = db().execute(
        """SELECT l.*, (SELECT COUNT(*) FROM clicks c WHERE c.link_id = l.id) AS clicks
           FROM links l WHERE user_id = ? ORDER BY created_at DESC""", (g.user["id"],)).fetchall()
    return jsonify([fmt(r) for r in rows])


def owned_link(link_id):
    return db().execute("SELECT * FROM links WHERE id = ? AND user_id = ?",
                        (link_id, g.user["id"])).fetchone()


@app.get("/api/v1/links/<int:link_id>/stats")
@login_required
def link_stats(link_id):
    link = owned_link(link_id)
    if not link:
        return err("Not found", 404)

    def q(sql):
        return [dict(r) for r in db().execute(sql, (link_id,)).fetchall()]

    total = db().execute("SELECT COUNT(*) n FROM clicks WHERE link_id = ?", (link_id,)).fetchone()["n"]
    return jsonify(
        link=fmt(link), totalClicks=total,
        referrers=q("SELECT COALESCE(referrer,'Direct') AS name, COUNT(*) AS count FROM clicks "
                    "WHERE link_id = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
        countries=q("SELECT COALESCE(country,'Unknown') AS name, COUNT(*) AS count FROM clicks "
                    "WHERE link_id = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
        daily=q("SELECT date(ts/1000,'unixepoch') AS day, COUNT(*) AS count FROM clicks "
                "WHERE link_id = ? GROUP BY 1 ORDER BY 1 DESC LIMIT 30"))


@app.delete("/api/v1/links/<int:link_id>")
@login_required
def delete_link(link_id):
    link = owned_link(link_id)
    if not link:
        return err("Not found", 404)
    db().execute("DELETE FROM links WHERE id = ?", (link_id,))
    db().commit()
    CACHE.pop(link["code"], None)
    return "", 204


# ---------- current user + admin dashboard ----------
@app.get("/api/v1/auth/me")
@login_required
def me():
    u = db().execute("SELECT email, is_admin FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if not u:
        return err("Unauthorized", 401)
    return jsonify(email=u["email"], isAdmin=bool(u["is_admin"]))


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        g.user = current_user()
        if not g.user:
            return err("Unauthorized", 401)
        u = db().execute("SELECT is_admin FROM users WHERE id = ?", (g.user["id"],)).fetchone()
        if not u or not u["is_admin"]:
            return err("Admin access required", 403)
        return fn(*a, **kw)
    return wrapper


@app.get("/api/v1/admin/overview")
@admin_required
def admin_overview():
    one = lambda t: db().execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"]
    rows = db().execute(
        """SELECT l.*, u.email AS owner, (SELECT COUNT(*) FROM clicks c WHERE c.link_id = l.id) AS clicks
           FROM links l LEFT JOIN users u ON u.id = l.user_id ORDER BY clicks DESC, l.id DESC LIMIT 50""").fetchall()
    return jsonify(users=one("users"), links=one("links"), clicks=one("clicks"),
                   allLinks=[fmt(r) for r in rows])


@app.delete("/api/v1/admin/links/<int:link_id>")
@admin_required
def admin_delete(link_id):
    row = db().execute("SELECT code FROM links WHERE id = ?", (link_id,)).fetchone()
    if not row:
        return err("Not found", 404)
    db().execute("DELETE FROM links WHERE id = ?", (link_id,))
    db().commit()
    CACHE.pop(row["code"], None)
    return "", 204


# ---------- redirect engine ----------
@app.get("/<code>")
@rate_limit("redirect", 300, 60)
def follow(code):
    link = cache_get(code)
    if not link:
        row = db().execute("SELECT id, url, expires_at FROM links WHERE code = ?", (code,)).fetchone()
        if not row:
            return "Link not found", 404
        link = dict(row)
        cache_set(code, link)
    if link["expires_at"] and link["expires_at"] < now_ms():
        return "Link expired", 410

    ref = request.referrer
    host = urlparse(ref).netloc if ref else None
    country = request.headers.get("CF-IPCountry") or request.headers.get("X-Vercel-IP-Country")
    try:
        db().execute("INSERT INTO clicks (link_id, ts, referrer, country, ua) VALUES (?,?,?,?,?)",
                     (link["id"], now_ms(), host, country, (request.user_agent.string or "")[:200]))
        db().commit()
    except sqlite3.Error:
        pass  # never block a redirect because of analytics
    return redirect(link["url"], code=302)


if __name__ == "__main__":
    print(f"Running at http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT)
