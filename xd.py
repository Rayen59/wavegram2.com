"""
HM Chat - Real-time messaging server
Author: Med Rayen Bouazizi

Single-file backend for an Android-style real-time chat application.
Features: single-use email registration, session tokens, direct messages,
groups with shareable invite links and optional admin password, profile
pictures, media messages (image/video/voice), message deletion, emoji
reactions, typing indicators, block/unblock, and full chat history so
nothing is lost on a page refresh.

Run:
    pip install flask flask-socketio flask-cors bcrypt pyjwt
    python3 hm.py
Then open http://<server-ip>:5000 in the browser.
"""

import os
import re
import sqlite3
import threading
import uuid
import time
import hashlib
import secrets
import bcrypt
import jwt
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_from_directory, g
from flask_socketio import SocketIO, join_room, emit
from flask_cors import CORS

# ===== CONFIGURATION =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hm.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
AVATAR_DIR = os.path.join(UPLOAD_DIR, "avatars")
MEDIA_DIR = os.path.join(UPLOAD_DIR, "media")
os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(MEDIA_DIR, exist_ok=True)

ALLOWED_MEDIA = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "webm",
                  "mp3", "wav", "ogg", "m4a", "3gp", "aac"}

JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
PUBLIC_BASE_URL = os.environ.get("HM_PUBLIC_URL", "").rstrip("/")
MAX_CONTENT_LENGTH = 60 * 1024 * 1024  # 60 MB

# If no public URL is set, use the local server address
if not PUBLIC_BASE_URL:
    PUBLIC_BASE_URL = "http://localhost:5000"

# ===== FLASK APP =====
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SECRET_KEY"] = JWT_SECRET
CORS(app, origins="*")

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                     max_http_buffer_size=MAX_CONTENT_LENGTH)

# ===== DATABASE =====

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

def db_conn():
    """Standalone connection for use inside Socket.IO handlers (no app context)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            status TEXT DEFAULT 'offline',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS groups(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            creator_id INTEGER NOT NULL,
            invite_token TEXT UNIQUE NOT NULL,
            password_hash TEXT DEFAULT '',
            avatar TEXT DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS group_members(
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member',
            joined_at REAL NOT NULL,
            PRIMARY KEY(group_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_type TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            msg_type TEXT NOT NULL,
            content TEXT DEFAULT '',
            media_path TEXT DEFAULT '',
            timestamp REAL NOT NULL,
            deleted INTEGER DEFAULT 0,
            reply_to_id INTEGER,
            forwarded_from_id INTEGER,
            edited INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS reactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            emoji TEXT NOT NULL,
            UNIQUE(message_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS blocks(
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            PRIMARY KEY(blocker_id, blocked_id)
        );
        CREATE TABLE IF NOT EXISTS read_state(
            user_id INTEGER NOT NULL,
            chat_type TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            last_read_id INTEGER DEFAULT 0,
            PRIMARY KEY(user_id, chat_type, chat_id)
        );
        CREATE TABLE IF NOT EXISTS hidden_messages(
            user_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            PRIMARY KEY(user_id, message_id)
        );
        CREATE TABLE IF NOT EXISTS reels(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            media_path TEXT NOT NULL,
            media_type TEXT NOT NULL,
            caption TEXT DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reel_views(
            reel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            viewed_at REAL NOT NULL,
            PRIMARY KEY(reel_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS reel_reactions(
            reel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            emoji TEXT NOT NULL,
            PRIMARY KEY(reel_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS reel_comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            parent_id INTEGER,
            created_at REAL NOT NULL
        );
    """)
    conn.commit()
    conn.close()

# ===== HELPERS =====

def dm_chat_id(uid1, uid2):
    a, b = sorted([int(uid1), int(uid2)])
    return f"{a}_{b}"

def hash_pw(pw):
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_pw(pw, stored):
    return bcrypt.checkpw(pw.encode('utf-8'), stored.encode('utf-8'))

def new_token():
    return secrets.token_urlsafe(32)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_MEDIA

def user_public(u):
    return {
        "id": u["id"],
        "username": u["username"],
        "email": u["email"],
        "avatar": u["avatar"],
        "status": u["status"]
    }

def preview_text(msg):
    if msg["msg_type"] == "text":
        t = msg["content"]
        return (t[:42] + "…") if len(t) > 42 else t
    if msg["msg_type"] == "call":
        parts = (msg["content"] or "audio:missed:0").split(":")
        ctype = parts[0] if len(parts) > 0 else "audio"
        status = parts[1] if len(parts) > 1 else "missed"
        icon = "🎥" if ctype == "video" else "📞"
        if status == "completed":
            return f"{icon} {'Video' if ctype=='video' else 'Voice'} call"
        if status == "declined":
            return f"{icon} Call declined"
        return f"{icon} Missed call"
    return {"image": "📷 Photo", "video": "🎬 Video", "voice": "🎤 Voice message"}.get(
        msg["msg_type"], "Message"
    )

def serialize_message(conn, r):
    reactions = conn.execute(
        "SELECT user_id, emoji FROM reactions WHERE message_id=?", (r["id"],)
    ).fetchall()
    sender = conn.execute(
        "SELECT username, avatar FROM users WHERE id=?", (r["sender_id"],)
    ).fetchone()

    reply_to = None
    if r["reply_to_id"]:
        orig = conn.execute("SELECT * FROM messages WHERE id=?", (r["reply_to_id"],)).fetchone()
        if orig:
            orig_sender = conn.execute("SELECT username FROM users WHERE id=?", (orig["sender_id"],)).fetchone()
            reply_to = {
                "id": orig["id"],
                "sender_name": orig_sender["username"] if orig_sender else "Unknown",
                "preview": preview_text(orig) if not orig["deleted"] else "Message deleted",
                "msg_type": orig["msg_type"],
            }

    forwarded_from_name = None
    if r["forwarded_from_id"]:
        orig_user = conn.execute("SELECT username FROM users WHERE id=?", (r["forwarded_from_id"],)).fetchone()
        forwarded_from_name = orig_user["username"] if orig_user else "Unknown"

    return {
        "id": r["id"],
        "chat_type": r["chat_type"],
        "chat_id": r["chat_id"],
        "sender_id": r["sender_id"],
        "sender_name": sender["username"] if sender else "Unknown",
        "sender_avatar": sender["avatar"] if sender else "",
        "msg_type": r["msg_type"],
        "content": "" if r["deleted"] else r["content"],
        "media_path": "" if r["deleted"] else r["media_path"],
        "timestamp": r["timestamp"],
        "deleted": bool(r["deleted"]),
        "edited": bool(r["edited"]),
        "reactions": [{"user_id": x["user_id"], "emoji": x["emoji"]} for x in reactions],
        "reply_to": reply_to,
        "forwarded_from_name": forwarded_from_name,
    }

def hidden_ids_for(db, uid):
    rows = db.execute("SELECT message_id FROM hidden_messages WHERE user_id=?", (uid,)).fetchall()
    return {r["message_id"] for r in rows}

def touch_read_state(db, uid, chat_type, chat_id, last_id):
    db.execute(
        "INSERT INTO read_state(user_id, chat_type, chat_id, last_read_id) VALUES (?,?,?,?) "
        "ON CONFLICT(user_id, chat_type, chat_id) DO UPDATE SET last_read_id=MAX(last_read_id, excluded.last_read_id)",
        (uid, chat_type, chat_id, last_id),
    )
    db.commit()

def rooms_for(chat_type, chat_id):
    if chat_type == "dm":
        a, b = chat_id.split("_")
        return [f"user:{a}", f"user:{b}"]
    return [f"group:{chat_id}"]

def generate_invite_link(token):
    """Generate a full international invite link for a group"""
    base_url = PUBLIC_BASE_URL.rstrip('/')
    return f"{base_url}/?join={token}"

# ===== AUTH DECORATOR =====

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Missing session token"}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
        if not user:
            return jsonify({"error": "Invalid or expired session"}), 401
        g.user = user
        return f(*args, **kwargs)
    return wrapper

# ===== AUTH ROUTES =====

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not email or "@" not in email:
        return jsonify({"error": "Please provide a valid email address"}), 400
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        return jsonify({"error": "This email has already been used to create an account"}), 409

    token = new_token()
    db.execute(
        "INSERT INTO users(email, username, password_hash, token, status, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (email, username, hash_pw(password), token, "online", time.time()),
    )
    db.commit()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return jsonify({"token": token, "user": user_public(user)})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not verify_pw(password, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401
    token = new_token()
    db.execute("UPDATE users SET token=?, status='online' WHERE id=?", (token, user["id"]))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    return jsonify({"token": token, "user": user_public(user)})

@app.route("/api/logout", methods=["POST"])
@auth_required
def logout():
    db = get_db()
    db.execute("UPDATE users SET token=NULL, status='offline' WHERE id=?", (g.user["id"],))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/account", methods=["DELETE"])
@auth_required
def delete_account():
    data = request.get_json(force=True) or {}
    password = data.get("password") or ""
    if not verify_pw(password, g.user["password_hash"]):
        return jsonify({"error": "Incorrect password"}), 403

    uid = g.user["id"]
    db = get_db()
    reel_files = db.execute("SELECT media_path FROM reels WHERE user_id=?", (uid,)).fetchall()

    try:
        db.execute("DELETE FROM messages WHERE sender_id=?", (uid,))
        db.execute("DELETE FROM reactions WHERE user_id=?", (uid,))
        db.execute("DELETE FROM reel_comments WHERE user_id=?", (uid,))
        db.execute("DELETE FROM reel_reactions WHERE user_id=?", (uid,))
        db.execute("DELETE FROM reel_views WHERE user_id=?", (uid,))
        db.execute("DELETE FROM reels WHERE user_id=?", (uid,))
        db.execute("DELETE FROM group_members WHERE user_id=?", (uid,))
        db.execute("DELETE FROM blocks WHERE blocker_id=? OR blocked_id=?", (uid, uid))
        db.execute("DELETE FROM read_state WHERE user_id=?", (uid,))
        db.execute("DELETE FROM hidden_messages WHERE user_id=?", (uid,))
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
    except Exception:
        db.rollback()
        return jsonify({"error": "Account deletion failed"}), 500

    for row in reel_files:
        try:
            path = row["media_path"].replace("/uploads/", "", 1)
            full = os.path.join(UPLOAD_DIR, path)
            if os.path.isfile(full):
                os.remove(full)
        except OSError:
            pass

    socketio.emit("account_deleted", {}, room=f"user:{uid}")
    return jsonify({"ok": True})

@app.route("/api/config", methods=["GET"])
def get_config():
    return jsonify({"public_base_url": PUBLIC_BASE_URL})

@app.route("/api/me", methods=["GET"])
@auth_required
def me():
    return jsonify({"user": user_public(g.user)})

@app.route("/api/profile", methods=["POST"])
@auth_required
def update_profile():
    username = request.form.get("username")
    avatar_file = request.files.get("avatar")
    db = get_db()
    if username:
        db.execute("UPDATE users SET username=? WHERE id=?", (username.strip(), g.user["id"]))
    if avatar_file and avatar_file.filename and allowed_file(avatar_file.filename):
        ext = avatar_file.filename.rsplit(".", 1)[1].lower()
        fname = f"{g.user['id']}_{uuid.uuid4().hex}.{ext}"
        avatar_file.save(os.path.join(AVATAR_DIR, fname))
        db.execute("UPDATE users SET avatar=? WHERE id=?",
                   (f"/uploads/avatars/{fname}", g.user["id"]))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
    return jsonify({"user": user_public(user)})

# ===== CONVERSATIONS =====

@app.route("/api/conversations", methods=["GET"])
@auth_required
def conversations():
    db = get_db()
    uid = g.user["id"]
    convos = []

    # Get DM conversations
    dm_chat_ids = db.execute("SELECT DISTINCT chat_id FROM messages WHERE chat_type='dm'").fetchall()
    for row in dm_chat_ids:
        cid = row["chat_id"]
        try:
            a, b = (int(x) for x in cid.split("_"))
        except ValueError:
            continue
        if uid not in (a, b):
            continue
        partner_id = b if a == uid else a
        partner = db.execute("SELECT * FROM users WHERE id=?", (partner_id,)).fetchone()
        if not partner:
            continue
        last_msg = db.execute(
            "SELECT * FROM messages WHERE chat_type='dm' AND chat_id=? ORDER BY id DESC LIMIT 1", (cid,)
        ).fetchone()
        if not last_msg:
            continue
        last_read = db.execute(
            "SELECT last_read_id FROM read_state WHERE user_id=? AND chat_type='dm' AND chat_id=?", (uid, cid)
        ).fetchone()
        last_read_id = last_read["last_read_id"] if last_read else 0
        unread = db.execute(
            "SELECT COUNT(*) c FROM messages WHERE chat_type='dm' AND chat_id=? AND sender_id!=? AND id>? AND deleted=0",
            (cid, uid, last_read_id)
        ).fetchone()["c"]
        convos.append({
            "type": "dm",
            "id": partner_id,
            "name": partner["username"],
            "avatar": partner["avatar"],
            "status": partner["status"],
            "last_preview": "Message deleted" if last_msg["deleted"] else preview_text(last_msg),
            "last_timestamp": last_msg["timestamp"],
            "last_is_mine": last_msg["sender_id"] == uid,
            "unread": unread,
        })

    # Get group conversations
    group_rows = db.execute(
        """SELECT g.*, m.role FROM groups g JOIN group_members m ON m.group_id = g.id
           WHERE m.user_id=?""", (uid,)
    ).fetchall()
    for grp in group_rows:
        last_msg = db.execute(
            "SELECT * FROM messages WHERE chat_type='group' AND chat_id=? ORDER BY id DESC LIMIT 1",
            (str(grp["id"]),)
        ).fetchone()
        preview, ts, is_mine = "No messages yet", grp["created_at"], False
        if last_msg:
            preview = "Message deleted" if last_msg["deleted"] else preview_text(last_msg)
            ts = last_msg["timestamp"]
            is_mine = last_msg["sender_id"] == uid
        last_read = db.execute(
            "SELECT last_read_id FROM read_state WHERE user_id=? AND chat_type='group' AND chat_id=?",
            (uid, str(grp["id"]))
        ).fetchone()
        last_read_id = last_read["last_read_id"] if last_read else 0
        unread = db.execute(
            "SELECT COUNT(*) c FROM messages WHERE chat_type='group' AND chat_id=? AND sender_id!=? AND id>? AND deleted=0",
            (str(grp["id"]), uid, last_read_id)
        ).fetchone()["c"]
        convos.append({
            "type": "group",
            "id": grp["id"],
            "name": grp["name"],
            "avatar": grp["avatar"],
            "status": "",
            "last_preview": preview,
            "last_timestamp": ts,
            "last_is_mine": is_mine,
            "role": grp["role"],
            "invite_token": grp["invite_token"],
            "has_password": bool(grp["password_hash"]),
            "unread": unread,
            "invite_link": generate_invite_link(grp["invite_token"])
        })

    convos.sort(key=lambda c: c["last_timestamp"], reverse=True)
    return jsonify({"conversations": convos})

@app.route("/api/unread_total", methods=["GET"])
@auth_required
def unread_total():
    r = conversations()
    data = r.get_json()
    total = sum(c["unread"] for c in data["conversations"])
    return jsonify({"total": total})

@app.route("/api/users/search", methods=["GET"])
@auth_required
def search_users():
    q = (request.args.get("q") or "").strip()
    db = get_db()
    if q:
        rows = db.execute(
            "SELECT * FROM users WHERE (username LIKE ? OR email LIKE ?) AND id != ? "
            "ORDER BY username LIMIT 30",
            (f"%{q}%", f"%{q}%", g.user["id"]),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM users WHERE id != ? ORDER BY username LIMIT 50", (g.user["id"],)
        ).fetchall()
    blocked = {
        r["blocked_id"]
        for r in db.execute("SELECT blocked_id FROM blocks WHERE blocker_id=?", (g.user["id"],))
    }
    return jsonify({"users": [user_public(u) for u in rows if u["id"] not in blocked]})

@app.route("/api/block", methods=["POST"])
@auth_required
def block_user():
    target_id = (request.get_json(force=True) or {}).get("user_id")
    db = get_db()
    db.execute("INSERT OR IGNORE INTO blocks(blocker_id, blocked_id) VALUES (?,?)",
               (g.user["id"], target_id))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/unblock", methods=["POST"])
@auth_required
def unblock_user():
    target_id = (request.get_json(force=True) or {}).get("user_id")
    db = get_db()
    db.execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?", (g.user["id"], target_id))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/block/status/<int:other_id>", methods=["GET"])
@auth_required
def block_status(other_id):
    db = get_db()
    i_blocked = db.execute(
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?", (g.user["id"], other_id)
    ).fetchone() is not None
    they_blocked = db.execute(
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?", (other_id, g.user["id"])
    ).fetchone() is not None
    return jsonify({"i_blocked": i_blocked, "they_blocked": they_blocked})

@app.route("/api/blocked", methods=["GET"])
@auth_required
def list_blocked():
    db = get_db()
    rows = db.execute(
        "SELECT u.* FROM users u JOIN blocks b ON b.blocked_id=u.id WHERE b.blocker_id=?",
        (g.user["id"],),
    ).fetchall()
    return jsonify({"users": [user_public(u) for u in rows]})

# ===== GROUPS =====

@app.route("/api/groups", methods=["POST"])
@auth_required
def create_group():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""
    if not name:
        return jsonify({"error": "Group name is required"}), 400
    db = get_db()
    token = secrets.token_urlsafe(12)
    pw_hash = hash_pw(password) if password else ""
    cur = db.execute(
        "INSERT INTO groups(name, creator_id, invite_token, password_hash, created_at) "
        "VALUES (?,?,?,?,?)",
        (name, g.user["id"], token, pw_hash, time.time()),
    )
    gid = cur.lastrowid
    db.execute(
        "INSERT INTO group_members(group_id, user_id, role, joined_at) VALUES (?,?,?,?)",
        (gid, g.user["id"], "admin", time.time()),
    )
    db.commit()
    
    # Return full group info with invite link
    return jsonify({
        "group": {
            "id": gid,
            "name": name,
            "invite_token": token,
            "has_password": bool(password),
            "role": "admin",
            "invite_link": generate_invite_link(token)
        }
    })

@app.route("/api/groups/mine", methods=["GET"])
@auth_required
def my_groups():
    db = get_db()
    rows = db.execute(
        """SELECT g.*, m.role FROM groups g
           JOIN group_members m ON m.group_id = g.id
           WHERE m.user_id=?""",
        (g.user["id"],),
    ).fetchall()
    return jsonify({
        "groups": [
            {
                "id": r["id"],
                "name": r["name"],
                "avatar": r["avatar"],
                "invite_token": r["invite_token"],
                "role": r["role"],
                "has_password": bool(r["password_hash"]),
                "invite_link": generate_invite_link(r["invite_token"])
            }
            for r in rows
        ]
    })

@app.route("/api/groups/join/<token>", methods=["POST"])
@auth_required
def join_group(token):
    password = (request.get_json(force=True) or {}).get("password", "")
    db = get_db()
    grp = db.execute("SELECT * FROM groups WHERE invite_token=?", (token,)).fetchone()
    if not grp:
        return jsonify({"error": "Invalid invite link"}), 404
    if grp["password_hash"] and not verify_pw(password, grp["password_hash"]):
        return jsonify({"error": "Incorrect group password"}), 403
    db.execute(
        "INSERT OR IGNORE INTO group_members(group_id, user_id, role, joined_at) VALUES (?,?,?,?)",
        (grp["id"], g.user["id"], "member", time.time()),
    )
    db.commit()
    return jsonify({
        "group": {
            "id": grp["id"],
            "name": grp["name"],
            "role": "member",
            "invite_link": generate_invite_link(grp["invite_token"])
        }
    })

@app.route("/api/groups/<int:gid>/members", methods=["GET"])
@auth_required
def group_members(gid):
    db = get_db()
    member = db.execute(
        "SELECT * FROM group_members WHERE group_id=? AND user_id=?", (gid, g.user["id"])
    ).fetchone()
    if not member:
        return jsonify({"error": "You are not a member of this group"}), 403
    rows = db.execute(
        """SELECT u.*, m.role FROM users u
           JOIN group_members m ON m.user_id = u.id
           WHERE m.group_id=?""",
        (gid,),
    ).fetchall()
    return jsonify({"members": [{**user_public(r), "role": r["role"]} for r in rows]})

@app.route("/api/groups/<int:gid>/avatar", methods=["POST"])
@auth_required
def group_avatar(gid):
    db = get_db()
    member = db.execute(
        "SELECT role FROM group_members WHERE group_id=? AND user_id=?", (gid, g.user["id"])
    ).fetchone()
    if not member or member["role"] != "admin":
        return jsonify({"error": "Only the group admin can change this"}), 403
    avatar_file = request.files.get("avatar")
    if not avatar_file or not allowed_file(avatar_file.filename):
        return jsonify({"error": "Invalid image"}), 400
    ext = avatar_file.filename.rsplit(".", 1)[1].lower()
    fname = f"g{gid}_{uuid.uuid4().hex}.{ext}"
    avatar_file.save(os.path.join(AVATAR_DIR, fname))
    db.execute("UPDATE groups SET avatar=? WHERE id=?", (f"/uploads/avatars/{fname}", gid))
    db.commit()
    return jsonify({"avatar": f"/uploads/avatars/{fname}"})

# ===== MEDIA UPLOAD =====

@app.route("/api/upload", methods=["POST"])
@auth_required
def upload_media():
    f = request.files.get("file")
    if not f or not f.filename or not allowed_file(f.filename):
        return jsonify({"error": "Invalid or missing file"}), 400
    ext = f.filename.rsplit(".", 1)[1].lower()
    fname = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(MEDIA_DIR, fname))
    return jsonify({"path": f"/uploads/media/{fname}"})

@app.route("/uploads/<path:subpath>")
def serve_upload(subpath):
    return send_from_directory(UPLOAD_DIR, subpath)

# ===== MESSAGES HISTORY =====

@app.route("/api/messages/dm/<int:other_id>", methods=["GET"])
@auth_required
def dm_history(other_id):
    db = get_db()
    chat_id = dm_chat_id(g.user["id"], other_id)
    rows = db.execute(
        "SELECT * FROM messages WHERE chat_type='dm' AND chat_id=? ORDER BY id ASC LIMIT 300",
        (chat_id,),
    ).fetchall()
    if rows:
        touch_read_state(db, g.user["id"], "dm", chat_id, rows[-1]["id"])
    hidden = hidden_ids_for(db, g.user["id"])
    return jsonify({"messages": [serialize_message(db, r) for r in rows if r["id"] not in hidden]})

@app.route("/api/messages/group/<int:gid>", methods=["GET"])
@auth_required
def group_history(gid):
    db = get_db()
    member = db.execute(
        "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (gid, g.user["id"])
    ).fetchone()
    if not member:
        return jsonify({"error": "You are not a member of this group"}), 403
    rows = db.execute(
        "SELECT * FROM messages WHERE chat_type='group' AND chat_id=? ORDER BY id ASC LIMIT 300",
        (str(gid),),
    ).fetchall()
    if rows:
        touch_read_state(db, g.user["id"], "group", str(gid), rows[-1]["id"])
    hidden = hidden_ids_for(db, g.user["id"])
    return jsonify({"messages": [serialize_message(db, r) for r in rows if r["id"] not in hidden]})

@app.route("/api/messages/<int:msg_id>/hide", methods=["POST"])
@auth_required
def hide_message(msg_id):
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO hidden_messages(user_id, message_id) VALUES (?,?)",
        (g.user["id"], msg_id),
    )
    db.commit()
    return jsonify({"ok": True})

# ===== REELS =====

def serialize_reel(db, r, uid):
    author = db.execute("SELECT username, avatar FROM users WHERE id=?", (r["user_id"],)).fetchone()
    view_count = db.execute("SELECT COUNT(*) c FROM reel_views WHERE reel_id=?", (r["id"],)).fetchone()["c"]
    reactions = db.execute("SELECT user_id, emoji FROM reel_reactions WHERE reel_id=?", (r["id"],)).fetchall()
    comment_count = db.execute("SELECT COUNT(*) c FROM reel_comments WHERE reel_id=?", (r["id"],)).fetchone()["c"]
    my_reaction = next((x["emoji"] for x in reactions if x["user_id"] == uid), None)
    return {
        "id": r["id"],
        "author_id": r["user_id"],
        "author_name": author["username"] if author else "Unknown",
        "author_avatar": author["avatar"] if author else "",
        "media_path": r["media_path"],
        "media_type": r["media_type"],
        "caption": r["caption"],
        "created_at": r["created_at"],
        "view_count": view_count,
        "comment_count": comment_count,
        "reaction_counts": _count_by_emoji(reactions),
        "my_reaction": my_reaction,
        "is_mine": r["user_id"] == uid,
    }

def _count_by_emoji(reactions):
    counts = {}
    for x in reactions:
        counts[x["emoji"]] = counts.get(x["emoji"], 0) + 1
    return counts

@app.route("/api/reels", methods=["POST"])
@auth_required
def create_reel():
    f = request.files.get("file")
    caption = (request.form.get("caption") or "").strip()
    if not f or not f.filename or not allowed_file(f.filename):
        return jsonify({"error": "Please attach a photo or video"}), 400
    ext = f.filename.rsplit(".", 1)[1].lower()
    media_type = "video" if ext in {"mp4", "mov", "webm", "3gp"} else "image"
    fname = f"reel_{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(MEDIA_DIR, fname))
    db = get_db()
    cur = db.execute(
        "INSERT INTO reels(user_id, media_path, media_type, caption, created_at) VALUES (?,?,?,?,?)",
        (g.user["id"], f"/uploads/media/{fname}", media_type, caption, time.time()),
    )
    db.commit()
    row = db.execute("SELECT * FROM reels WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify({"reel": serialize_reel(db, row, g.user["id"])})

@app.route("/api/reels", methods=["GET"])
@auth_required
def list_reels():
    db = get_db()
    rows = db.execute("SELECT * FROM reels ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify({"reels": [serialize_reel(db, r, g.user["id"]) for r in rows]})

@app.route("/api/reels/<int:rid>", methods=["DELETE"])
@auth_required
def delete_reel(rid):
    db = get_db()
    row = db.execute("SELECT * FROM reels WHERE id=?", (rid,)).fetchone()
    if not row or row["user_id"] != g.user["id"]:
        return jsonify({"error": "You can only delete your own reels"}), 403
    
    # Delete the file
    try:
        path = row["media_path"].replace("/uploads/", "", 1)
        full = os.path.join(UPLOAD_DIR, path)
        if os.path.isfile(full):
            os.remove(full)
    except OSError:
        pass
    
    db.execute("DELETE FROM reels WHERE id=?", (rid,))
    db.execute("DELETE FROM reel_views WHERE reel_id=?", (rid,))
    db.execute("DELETE FROM reel_reactions WHERE reel_id=?", (rid,))
    db.execute("DELETE FROM reel_comments WHERE reel_id=?", (rid,))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/reels/<int:rid>/view", methods=["POST"])
@auth_required
def view_reel(rid):
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO reel_views(reel_id, user_id, viewed_at) VALUES (?,?,?)",
        (rid, g.user["id"], time.time()),
    )
    db.commit()
    count = db.execute("SELECT COUNT(*) c FROM reel_views WHERE reel_id=?", (rid,)).fetchone()["c"]
    return jsonify({"view_count": count})

@app.route("/api/reels/<int:rid>/react", methods=["POST"])
@auth_required
def react_reel(rid):
    emoji = (request.get_json(force=True) or {}).get("emoji")
    db = get_db()
    if not emoji:
        db.execute("DELETE FROM reel_reactions WHERE reel_id=? AND user_id=?", (rid, g.user["id"]))
    else:
        db.execute(
            "INSERT INTO reel_reactions(reel_id, user_id, emoji) VALUES (?,?,?) "
            "ON CONFLICT(reel_id, user_id) DO UPDATE SET emoji=excluded.emoji",
            (rid, g.user["id"], emoji),
        )
    db.commit()
    reactions = db.execute("SELECT user_id, emoji FROM reel_reactions WHERE reel_id=?", (rid,)).fetchall()
    return jsonify({"reaction_counts": _count_by_emoji(reactions)})

def serialize_comment(db, c):
    author = db.execute("SELECT username, avatar FROM users WHERE id=?", (c["user_id"],)).fetchone()
    return {
        "id": c["id"],
        "reel_id": c["reel_id"],
        "user_id": c["user_id"],
        "author_name": author["username"] if author else "Unknown",
        "author_avatar": author["avatar"] if author else "",
        "content": c["content"],
        "parent_id": c["parent_id"],
        "created_at": c["created_at"],
    }

@app.route("/api/reels/<int:rid>/comments", methods=["GET"])
@auth_required
def get_comments(rid):
    db = get_db()
    rows = db.execute("SELECT * FROM reel_comments WHERE reel_id=? ORDER BY id ASC", (rid,)).fetchall()
    return jsonify({"comments": [serialize_comment(db, c) for c in rows]})

@app.route("/api/reels/<int:rid>/comments", methods=["POST"])
@auth_required
def post_comment(rid):
    data = request.get_json(force=True) or {}
    content = (data.get("content") or "").strip()
    parent_id = data.get("parent_id")
    if not content:
        return jsonify({"error": "Comment cannot be empty"}), 400
    db = get_db()
    reel = db.execute("SELECT 1 FROM reels WHERE id=?", (rid,)).fetchone()
    if not reel:
        return jsonify({"error": "Reel not found"}), 404
    if parent_id:
        parent = db.execute("SELECT 1 FROM reel_comments WHERE id=? AND reel_id=?", (parent_id, rid)).fetchone()
        if not parent:
            parent_id = None
    cur = db.execute(
        "INSERT INTO reel_comments(reel_id, user_id, content, parent_id, created_at) VALUES (?,?,?,?,?)",
        (rid, g.user["id"], content, parent_id, time.time()),
    )
    db.commit()
    row = db.execute("SELECT * FROM reel_comments WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify({"comment": serialize_comment(db, row)})

@app.route("/api/reels/comments/<int:cid>", methods=["DELETE"])
@auth_required
def delete_comment(cid):
    db = get_db()
    row = db.execute("SELECT * FROM reel_comments WHERE id=?", (cid,)).fetchone()
    if not row or row["user_id"] != g.user["id"]:
        return jsonify({"error": "You can only delete your own comments"}), 403
    db.execute("DELETE FROM reel_comments WHERE id=? OR parent_id=?", (cid, cid))
    db.commit()
    return jsonify({"ok": True})

# ===== SOCKET.IO EVENTS =====

sid_to_user = {}

@socketio.on("connect")
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on("disconnect")
def handle_disconnect():
    uid = sid_to_user.pop(request.sid, None)
    if uid:
        conn = db_conn()
        conn.execute("UPDATE users SET status='offline' WHERE id=?", (uid,))
        conn.commit()
        conn.close()
    print(f"Client disconnected: {request.sid}")

@socketio.on("auth")
def sio_auth(data):
    token = (data or {}).get("token")
    conn = db_conn()
    user = conn.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    if not user:
        emit("auth_error", {"error": "Invalid session"})
        conn.close()
        return
    sid_to_user[request.sid] = user["id"]
    join_room(f"user:{user['id']}")
    for grow in conn.execute("SELECT group_id FROM group_members WHERE user_id=?", (user["id"],)):
        join_room(f"group:{grow['group_id']}")
    conn.execute("UPDATE users SET status='online' WHERE id=?", (user["id"],))
    conn.commit()
    conn.close()
    emit("auth_ok", {"user_id": user["id"]})

@socketio.on("send_message")
def sio_send_message(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        emit("error_msg", {"error": "Not authenticated"})
        return

    chat_type = (data or {}).get("chat_type")
    target = (data or {}).get("target")
    msg_type = (data or {}).get("msg_type", "text")
    content = (data or {}).get("content", "")
    media_path = (data or {}).get("media_path", "")
    reply_to_id = (data or {}).get("reply_to_id")
    client_id = (data or {}).get("client_id")

    if chat_type not in ("dm", "group") or target is None:
        emit("error_msg", {"error": "Malformed message"})
        return
    if msg_type == "text" and not content.strip():
        emit("error_msg", {"error": "Empty message"})
        return

    conn = db_conn()
    if chat_type == "dm":
        target_user = conn.execute("SELECT 1 FROM users WHERE id=?", (target,)).fetchone()
        if not target_user:
            emit("error_msg", {"error": "This account no longer exists"})
            conn.close()
            return
        blocked = conn.execute(
            "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) "
            "OR (blocker_id=? AND blocked_id=?)",
            (target, uid, uid, target),
        ).fetchone()
        if blocked:
            emit("error_msg", {"error": "You cannot message this user"})
            conn.close()
            return
        chat_id = dm_chat_id(uid, target)
    else:
        member = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (target, uid)
        ).fetchone()
        if not member:
            emit("error_msg", {"error": "Not a group member"})
            conn.close()
            return
        chat_id = str(target)

    if reply_to_id:
        orig = conn.execute(
            "SELECT 1 FROM messages WHERE id=? AND chat_type=? AND chat_id=? AND deleted=0",
            (reply_to_id, chat_type, chat_id),
        ).fetchone()
        if not orig:
            reply_to_id = None

    cur = conn.execute(
        "INSERT INTO messages(chat_type, chat_id, sender_id, msg_type, content, media_path, timestamp, reply_to_id) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (chat_type, chat_id, uid, msg_type, content, media_path, time.time(), reply_to_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
    payload = serialize_message(conn, row)
    payload["client_id"] = client_id
    conn.close()

    for room in rooms_for(chat_type, chat_id):
        emit("new_message", payload, room=room)

@socketio.on("forward_message")
def sio_forward_message(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        emit("error_msg", {"error": "Not authenticated"})
        return
    message_id = (data or {}).get("message_id")
    chat_type = (data or {}).get("chat_type")
    target = (data or {}).get("target")
    client_id = (data or {}).get("client_id")

    if chat_type not in ("dm", "group") or target is None or not message_id:
        emit("error_msg", {"error": "Malformed forward request"})
        return

    conn = db_conn()
    orig = conn.execute("SELECT * FROM messages WHERE id=? AND deleted=0", (message_id,)).fetchone()
    if not orig:
        emit("error_msg", {"error": "Original message not found"})
        conn.close()
        return

    if chat_type == "dm":
        target_user = conn.execute("SELECT 1 FROM users WHERE id=?", (target,)).fetchone()
        if not target_user:
            emit("error_msg", {"error": "This account no longer exists"})
            conn.close()
            return
        blocked = conn.execute(
            "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",
            (target, uid, uid, target),
        ).fetchone()
        if blocked:
            emit("error_msg", {"error": "You cannot message this user"})
            conn.close()
            return
        chat_id = dm_chat_id(uid, target)
    else:
        member = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (target, uid)
        ).fetchone()
        if not member:
            emit("error_msg", {"error": "Not a group member"})
            conn.close()
            return
        chat_id = str(target)

    cur = conn.execute(
        "INSERT INTO messages(chat_type, chat_id, sender_id, msg_type, content, media_path, timestamp, forwarded_from_id) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (chat_type, chat_id, uid, orig["msg_type"], orig["content"], orig["media_path"], time.time(), orig["sender_id"]),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
    payload = serialize_message(conn, row)
    payload["client_id"] = client_id
    conn.close()

    for room in rooms_for(chat_type, chat_id):
        emit("new_message", payload, room=room)

@socketio.on("mark_read")
def sio_mark_read(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    chat_type = (data or {}).get("chat_type")
    target = (data or {}).get("target")
    if chat_type not in ("dm", "group") or target is None:
        return
    chat_id = dm_chat_id(uid, target) if chat_type == "dm" else str(target)
    conn = db_conn()
    last = conn.execute(
        "SELECT MAX(id) m FROM messages WHERE chat_type=? AND chat_id=?", (chat_type, chat_id)
    ).fetchone()
    last_id = last["m"] or 0
    touch_read_state(conn, uid, chat_type, chat_id, last_id)
    conn.close()

@socketio.on("delete_message")
def sio_delete_message(data):
    uid = sid_to_user.get(request.sid)
    msg_id = (data or {}).get("message_id")
    if not uid or not msg_id:
        return
    conn = db_conn()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row or row["sender_id"] != uid:
        emit("error_msg", {"error": "You can only delete your own messages"})
        conn.close()
        return
    conn.execute("UPDATE messages SET deleted=1, content='', media_path='' WHERE id=?", (msg_id,))
    conn.commit()
    chat_type, chat_id = row["chat_type"], row["chat_id"]
    conn.close()
    for room in rooms_for(chat_type, chat_id):
        emit("message_deleted", {"message_id": msg_id}, room=room)

@socketio.on("edit_message")
def sio_edit_message(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        emit("error_msg", {"error": "Not authenticated"})
        return
    msg_id = (data or {}).get("message_id")
    new_content = (data or {}).get("content", "").strip()
    if not msg_id or not new_content:
        return
    conn = db_conn()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row or row["sender_id"] != uid or row["deleted"] or row["msg_type"] != "text":
        emit("error_msg", {"error": "This message can't be edited"})
        conn.close()
        return
    conn.execute("UPDATE messages SET content=?, edited=1 WHERE id=?", (new_content, msg_id))
    conn.commit()
    chat_type, chat_id = row["chat_type"], row["chat_id"]
    conn.close()
    for room in rooms_for(chat_type, chat_id):
        emit("message_edited", {"message_id": msg_id, "content": new_content}, room=room)

@socketio.on("react_message")
def sio_react(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    msg_id = (data or {}).get("message_id")
    emoji = (data or {}).get("emoji")
    if not msg_id or not emoji:
        return
    conn = db_conn()
    row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row:
        conn.close()
        return
    conn.execute(
        "INSERT INTO reactions(message_id, user_id, emoji) VALUES (?,?,?) "
        "ON CONFLICT(message_id, user_id) DO UPDATE SET emoji=excluded.emoji",
        (msg_id, uid, emoji),
    )
    conn.commit()
    chat_type, chat_id = row["chat_type"], row["chat_id"]
    conn.close()
    for room in rooms_for(chat_type, chat_id):
        emit("message_reacted", {"message_id": msg_id, "user_id": uid, "emoji": emoji}, room=room)

@socketio.on("typing")
def sio_typing(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    chat_type = (data or {}).get("chat_type")
    target = (data or {}).get("target")
    if chat_type not in ("dm", "group") or target is None:
        return
    if chat_type == "dm":
        emit("typing", {"from": uid}, room=f"user:{target}")
    else:
        emit("typing", {"from": uid}, room=f"group:{target}", include_self=False)

# ===== CALL EVENTS =====

@socketio.on("call_offer")
def sio_call_offer(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    target = (data or {}).get("target")
    offer = (data or {}).get("offer")
    call_type = (data or {}).get("call_type", "audio")
    if target is None or not offer:
        return
    conn = db_conn()
    caller = conn.execute("SELECT username, avatar FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    emit("call_offer", {
        "from": uid,
        "from_name": caller["username"] if caller else "Unknown",
        "from_avatar": caller["avatar"] if caller else "",
        "call_type": call_type,
        "offer": offer,
    }, room=f"user:{target}")

@socketio.on("call_answer")
def sio_call_answer(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    target = (data or {}).get("target")
    answer = (data or {}).get("answer")
    if target is None or not answer:
        return
    emit("call_answer", {"from": uid, "answer": answer}, room=f"user:{target}")

@socketio.on("call_ice_candidate")
def sio_call_ice(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    target = (data or {}).get("target")
    candidate = (data or {}).get("candidate")
    if target is None or not candidate:
        return
    emit("call_ice_candidate", {"from": uid, "candidate": candidate}, room=f"user:{target}")

@socketio.on("call_reject")
def sio_call_reject(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    target = (data or {}).get("target")
    if target is None:
        return
    emit("call_reject", {"from": uid, "reason": (data or {}).get("reason", "declined")}, room=f"user:{target}")

@socketio.on("call_end")
def sio_call_end(data):
    uid = sid_to_user.get(request.sid)
    if not uid:
        return
    target = (data or {}).get("target")
    if target is None:
        return
    emit("call_end", {"from": uid}, room=f"user:{target}")

# ===== FRONTEND =====

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "hm.html")

def try_start_public_tunnel():
    """Best-effort attempt to give this server a real internet address."""
    global PUBLIC_BASE_URL
    if PUBLIC_BASE_URL and PUBLIC_BASE_URL != "http://localhost:5000":
        print(f"Using configured public URL: {PUBLIC_BASE_URL}")
        return

    def runner():
        global PUBLIC_BASE_URL
        try:
            proc = subprocess.Popen(
                ["cloudflared", "tunnel", "--url", "http://localhost:5000"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            print("\nNote: Install cloudflared for public invite links:\n    pkg install cloudflared (Termux)\n")
            return
        pattern = re.compile(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com")
        for line in proc.stdout:
            m = pattern.search(line)
            if m:
                PUBLIC_BASE_URL = m.group(0)
                print(f"\n✔ Public URL: {PUBLIC_BASE_URL}\n")
                break

    threading.Thread(target=runner, daemon=True).start()

# ===== RUN =====

if __name__ == "__main__":
    init_db()
    print("🚀 HM Chat Server starting on http://0.0.0.0:5000")
    print(f"📡 Invite links will use: {PUBLIC_BASE_URL}")
    try_start_public_tunnel()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
