# =============================================================================
#  HM CHAT – SERVER (Python + Flask + Flask-SocketIO)
#  Real-time messaging, calls, groups, reels, blocking, and more.
#  Inspired by Telegram's speed and reliability.
# =============================================================================

import os
import json
import uuid
import hashlib
import bcrypt
import jwt
import datetime
import time
import base64
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from werkzeug.utils import secure_filename
import threading
import queue

# ===== CONFIGURATION =====
PORT = int(os.environ.get('PORT', 3000))
JWT_SECRET = os.environ.get('JWT_SECRET', 'hm_chat_super_secret_key_change_me')
PUBLIC_BASE_URL = os.environ.get('PUBLIC_BASE_URL', '')
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'mov', 'mp3', 'wav', 'ogg'}

# ===== DATABASE (In-memory for simplicity – use Redis/Postgres in production) =====
DB = {
    'users': {},          # user_id -> {id, username, email, password_hash, avatar, status, blocked_ids, created_at}
    'sessions': {},       # token -> user_id
    'messages': {},       # message_id -> {id, chat_type, chat_id, sender_id, sender_name, msg_type, content, media_path, timestamp, deleted, edited, reactions, reply_to, forwarded_from, client_id}
    'conversations': {},  # composite_key "dm:user_id" or "group:group_id" -> {id, type, name, avatar, last_message, unread}
    'groups': {},         # group_id -> {id, name, avatar, admin_id, members, invite_token, has_password, password_hash, created_at}
    'reels': [],          # list of {id, author_id, author_name, author_avatar, media_path, media_type, caption, view_count, reactions, comments, created_at}
    'comments': {},       # reel_id -> [comment]
    'notifications': {},  # user_id -> [notification]
}

# ===== FLASK APP =====
app = Flask(__name__)
app.config['SECRET_KEY'] = JWT_SECRET
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

CORS(app, origins='*')

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ===== SOCKET.IO (Corrigé pour éviter l'erreur async_mode sur Render) =====
socketio = SocketIO(app, cors_allowed_origins='*', ping_timeout=60)

# ===== AUTHENTICATION DECORATOR =====
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        if token.startswith('Bearer '):
            token = token[7:]
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            user_id = data['user_id']
            if user_id not in DB['users']:
                return jsonify({'error': 'Invalid token'}), 401
            request.user_id = user_id
            request.user = DB['users'][user_id]
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# ===== HELPER FUNCTIONS =====
def generate_id():
    return str(int(time.time() * 1000)) + '_' + uuid.uuid4().hex[:8]

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_token(user_id):
    return jwt.encode({'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)}, JWT_SECRET, algorithm='HS256')

def get_conversation_key(chat_type, chat_id):
    return f"{chat_type}:{chat_id}"

def get_or_create_conversation(user_id, chat_type, chat_id, name=None, avatar=None):
    key = get_conversation_key(chat_type, chat_id)
    if key in DB['conversations']:
        return DB['conversations'][key]
    
    conv = {
        'id': chat_id,
        'type': chat_type,
        'name': name or 'Unknown',
        'avatar': avatar or '',
        'last_message': '',
        'last_timestamp': time.time(),
        'unread': 0
    }
    DB['conversations'][key] = conv
    return conv

def update_conversation(user_id, chat_type, chat_id, message):
    key = get_conversation_key(chat_type, chat_id)
    if key in DB['conversations']:
        conv = DB['conversations'][key]
        conv['last_message'] = message.get('preview', message.get('content', ''))
        conv['last_timestamp'] = message.get('timestamp', time.time())
        if message.get('sender_id') != user_id:
            conv['unread'] = conv.get('unread', 0) + 1
    else:
        if chat_type == 'dm':
            other_user = DB['users'].get(chat_id)
            name = other_user['username'] if other_user else 'Unknown'
            avatar = other_user.get('avatar', '') if other_user else ''
        else:
            group = DB['groups'].get(chat_id)
            name = group['name'] if group else 'Unknown'
            avatar = group.get('avatar', '') if group else ''
        conv = {
            'id': chat_id,
            'type': chat_type,
            'name': name,
            'avatar': avatar,
            'last_message': message.get('preview', message.get('content', '')),
            'last_timestamp': message.get('timestamp', time.time()),
            'unread': 1 if message.get('sender_id') != user_id else 0
        }
        DB['conversations'][key] = conv

def format_user(user):
    return {
        'id': user['id'],
        'username': user['username'],
        'email': user.get('email', ''),
        'avatar': user.get('avatar', ''),
        'status': user.get('status', 'offline'),
        'created_at': user.get('created_at', time.time())
    }

def format_message(msg):
    return {
        'id': msg['id'],
        'chat_type': msg['chat_type'],
        'chat_id': msg['chat_id'],
        'sender_id': msg['sender_id'],
        'sender_name': msg.get('sender_name', ''),
        'sender_avatar': msg.get('sender_avatar', ''),
        'msg_type': msg.get('msg_type', 'text'),
        'content': msg.get('content', ''),
        'media_path': msg.get('media_path', ''),
        'timestamp': msg.get('timestamp', time.time()),
        'deleted': msg.get('deleted', False),
        'edited': msg.get('edited', False),
        'reactions': msg.get('reactions', []),
        'reply_to': msg.get('reply_to'),
        'forwarded_from': msg.get('forwarded_from'),
        'client_id': msg.get('client_id'),
        'preview': msg.get('preview', msg.get('content', '')[:50])
    }

# ===== ROUTES =====

@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        'public_base_url': PUBLIC_BASE_URL,
        'version': '2.0.0'
    })

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    
    for user in DB['users'].values():
        if user['username'].lower() == username.lower():
            return jsonify({'error': 'Username already taken'}), 400
        if user['email'].lower() == email:
            return jsonify({'error': 'Email already registered'}), 400
    
    user_id = generate_id()
    user = {
        'id': user_id,
        'username': username,
        'email': email,
        'password_hash': hash_password(password),
        'avatar': '',
        'status': 'offline',
        'blocked_ids': [],
        'created_at': time.time()
    }
    DB['users'][user_id] = user
    
    token = generate_token(user_id)
    DB['sessions'][token] = user_id
    
    return jsonify({
        'token': token,
        'user': format_user(user)
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    user = None
    for u in DB['users'].values():
        if u['email'].lower() == email:
            user = u
            break
    
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401
    
    if not verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    token = generate_token(user['id'])
    DB['sessions'][token] = user['id']
    user['status'] = 'online'
    
    return jsonify({
        'token': token,
        'user': format_user(user)
    })

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token in DB['sessions']:
        del DB['sessions'][token]
    user = DB['users'].get(request.user_id)
    if user:
        user['status'] = 'offline'
    return jsonify({'success': True})

@app.route('/api/me', methods=['GET'])
@token_required
def get_me():
    return jsonify({'user': format_user(request.user)})

@app.route('/api/profile', methods=['POST'])
@token_required
def update_profile():
    user = request.user
    if request.files and 'avatar' in request.files:
        file = request.files['avatar']
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"avatar_{user['id']}.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            user['avatar'] = f"/uploads/{filename}"
            return jsonify({'user': format_user(user)})
    
    data = request.get_json() or {}
    if 'username' in data:
        username = data['username'].strip()
        if username:
            for u in DB['users'].values():
                if u['id'] != user['id'] and u['username'].lower() == username.lower():
                    return jsonify({'error': 'Username already taken'}), 400
            user['username'] = username
    
    return jsonify({'user': format_user(user)})

@app.route('/api/users/search', methods=['GET'])
@token_required
def search_users():
    q = request.args.get('q', '').strip().lower()
    users = []
    for u in DB['users'].values():
        if u['id'] == request.user_id:
            continue
        if q and q not in u['username'].lower():
            continue
        users.append(format_user(u))
    return jsonify({'users': users})

@app.route('/api/conversations', methods=['GET'])
@token_required
def get_conversations():
    user_id = request.user_id
    convs = []
    for key, conv in DB['conversations'].items():
        if key.startswith('dm:') and conv['id'] != user_id:
            other_id = conv['id']
            if other_id in request.user.get('blocked_ids', []):
                continue
            other = DB['users'].get(other_id)
            if other and other_id in other.get('blocked_ids', []):
                continue
        convs.append({
            'id': conv['id'],
            'type': conv['type'],
            'name': conv['name'],
            'avatar': conv.get('avatar', ''),
            'last_preview': conv.get('last_message', ''),
            'last_timestamp': conv.get('last_timestamp', time.time()),
            'last_is_mine': False,
            'unread': conv.get('unread', 0),
            'status': 'online' if conv['type'] == 'dm' and DB['users'].get(conv['id'], {}).get('status') == 'online' else 'offline'
        })
    convs.sort(key=lambda x: x.get('last_timestamp', 0), reverse=True)
    return jsonify({'conversations': convs})

@app.route('/api/unread_total', methods=['GET'])
@token_required
def get_unread_total():
    total = 0
    for key, conv in DB['conversations'].items():
        total += conv.get('unread', 0)
    return jsonify({'total': total})

@app.route('/api/messages/dm/<user_id>', methods=['GET'])
@token_required
def get_dm_messages(user_id):
    if user_id in request.user.get('blocked_ids', []):
        return jsonify({'error': 'Blocked'}), 403
    other = DB['users'].get(user_id)
    if other and user_id in other.get('blocked_ids', []):
        return jsonify({'error': 'Blocked'}), 403
    
    messages = []
    for msg in DB['messages'].values():
        if msg['chat_type'] == 'dm' and (
            (msg['sender_id'] == request.user_id and msg['chat_id'] == user_id) or
            (msg['sender_id'] == user_id and msg['chat_id'] == request.user_id)
        ):
            if not msg.get('deleted', False):
                messages.append(format_message(msg))
    
    messages.sort(key=lambda x: x['timestamp'])
    return jsonify({'messages': messages})

@app.route('/api/messages/group/<group_id>', methods=['GET'])
@token_required
def get_group_messages(group_id):
    group = DB['groups'].get(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    if request.user_id not in group.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    messages = []
    for msg in DB['messages'].values():
        if msg['chat_type'] == 'group' and msg['chat_id'] == group_id:
            if not msg.get('deleted', False):
                messages.append(format_message(msg))
    
    messages.sort(key=lambda x: x['timestamp'])
    return jsonify({'messages': messages})

@app.route('/api/messages/<message_id>/hide', methods=['POST'])
@token_required
def hide_message(message_id):
    msg = DB['messages'].get(message_id)
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    msg['deleted'] = True
    return jsonify({'success': True})

@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if not file:
        return jsonify({'error': 'No file provided'}), 400
    
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({'error': 'File type not allowed'}), 400
    
    new_filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
    file.save(filepath)
    
    return jsonify({'path': f"/uploads/{new_filename}"})

@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ===== GROUP ROUTES =====

@app.route('/api/groups', methods=['POST'])
@token_required
def create_group():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    password = data.get('password', '')
    
    if not name:
        return jsonify({'error': 'Group name required'}), 400
    
    group_id = generate_id()
    group = {
        'id': group_id,
        'name': name,
        'avatar': '',
        'admin_id': request.user_id,
        'members': [request.user_id],
        'invite_token': uuid.uuid4().hex[:12],
        'has_password': bool(password),
        'password_hash': hash_password(password) if password else '',
        'created_at': time.time()
    }
    DB['groups'][group_id] = group
    get_or_create_conversation(request.user_id, 'group', group_id, name, '')
    
    return jsonify({'group': group})

@app.route('/api/groups/mine', methods=['GET'])
@token_required
def get_my_groups():
    groups = []
    for g in DB['groups'].values():
        if request.user_id in g.get('members', []):
            groups.append({
                'id': g['id'],
                'name': g['name'],
                'avatar': g.get('avatar', ''),
                'role': 'admin' if g.get('admin_id') == request.user_id else 'member',
                'has_password': g.get('has_password', False),
                'invite_token': g.get('invite_token', ''),
                'member_count': len(g.get('members', []))
            })
    return jsonify({'groups': groups})

@app.route('/api/groups/<group_id>/members', methods=['GET'])
@token_required
def get_group_members(group_id):
    group = DB['groups'].get(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    if request.user_id not in group.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    
    members = []
    for uid in group.get('members', []):
        user = DB['users'].get(uid)
        if user:
            members.append({
                'id': user['id'],
                'username': user['username'],
                'avatar': user.get('avatar', ''),
                'role': 'admin' if uid == group.get('admin_id') else 'member'
            })
    return jsonify({'members': members})

@app.route('/api/groups/<group_id>/avatar', methods=['POST'])
@token_required
def update_group_avatar(group_id):
    group = DB['groups'].get(group_id)
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    
    if group.get('admin_id') != request.user_id:
        return jsonify({'error': 'Only admin can change avatar'}), 403
    
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['avatar']
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"group_{group_id}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        group['avatar'] = f"/uploads/{filename}"
        return jsonify({'avatar': group['avatar']})
    
    return jsonify({'error': 'Invalid file'}), 400

@app.route('/api/groups/join/<invite_token>', methods=['POST'])
@token_required
def join_group(invite_token):
    group = None
    for g in DB['groups'].values():
        if g.get('invite_token') == invite_token:
            group = g
            break
    
    if not group:
        return jsonify({'error': 'Invalid invite token'}), 404
    
    if request.user_id in group.get('members', []):
        return jsonify({'error': 'Already a member'}), 400
    
    if group.get('has_password'):
        data = request.get_json() or {}
        password = data.get('password', '')
        if not verify_password(password, group.get('password_hash', '')):
            return jsonify({'error': 'Incorrect password'}), 403
    
    group['members'].append(request.user_id)
    get_or_create_conversation(request.user_id, 'group', group['id'], group['name'], group.get('avatar', ''))
    
    return jsonify({'success': True})

# ===== BLOCK ROUTES =====

@app.route('/api/block', methods=['POST'])
@token_required
def block_user():
    data = request.get_json() or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID required'}), 400
    
    if user_id == request.user_id:
        return jsonify({'error': 'Cannot block yourself'}), 400
    
    if user_id not in DB['users']:
        return jsonify({'error': 'User not found'}), 404
    
    if user_id not in request.user.get('blocked_ids', []):
        request.user['blocked_ids'].append(user_id)
    
    return jsonify({'success': True})

@app.route('/api/unblock', methods=['POST'])
@token_required
def unblock_user():
    data = request.get_json() or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID required'}), 400
    
    if user_id in request.user.get('blocked_ids', []):
        request.user['blocked_ids'].remove(user_id)
    
    return jsonify({'success': True})

@app.route('/api/blocked', methods=['GET'])
@token_required
def get_blocked():
    users = []
    for uid in request.user.get('blocked_ids', []):
        user = DB['users'].get(uid)
        if user:
            users.append({'id': user['id'], 'username': user['username']})
    return jsonify({'users': users})

@app.route('/api/block/status/<user_id>', methods=['GET'])
@token_required
def get_block_status(user_id):
    i_blocked = user_id in request.user.get('blocked_ids', [])
    other = DB['users'].get(user_id)
    they_blocked = other and user_id in other.get('blocked_ids', [])
    return jsonify({'i_blocked': i_blocked, 'they_blocked': they_blocked})

# ===== ACCOUNT ROUTES =====

@app.route('/api/account', methods=['DELETE'])
@token_required
def delete_account():
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if not verify_password(password, request.user['password_hash']):
        return jsonify({'error': 'Incorrect password'}), 403
    
    user_id = request.user_id
    if user_id in DB['users']:
        del DB['users'][user_id]
    
    for token, uid in list(DB['sessions'].items()):
        if uid == user_id:
            del DB['sessions'][token]
    
    for msg in DB['messages'].values():
        if msg['sender_id'] == user_id:
            msg['deleted'] = True
    
    for group in list(DB['groups'].values()):
        if user_id in group.get('members', []):
            group['members'].remove(user_id)
        if group.get('admin_id') == user_id:
            if group.get('members'):
                group['admin_id'] = group['members'][0]
            else:
                del DB['groups'][group['id']]
    
    return jsonify({'success': True})

# ===== REELS ROUTES =====

@app.route('/api/reels', methods=['GET'])
@token_required
def get_reels():
    return jsonify({'reels': DB['reels'][:50]})

@app.route('/api/reels', methods=['POST'])
@token_required
def create_reel():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    caption = request.form.get('caption', '')
    
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({'error': 'File type not allowed'}), 400
    
    filename = f"reel_{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    media_type = 'video' if ext in {'mp4', 'webm', 'mov'} else 'image'
    
    reel = {
        'id': generate_id(),
        'author_id': request.user_id,
        'author_name': request.user['username'],
        'author_avatar': request.user.get('avatar', ''),
        'media_path': f"/uploads/{filename}",
        'media_type': media_type,
        'caption': caption,
        'view_count': 0,
        'reaction_counts': {},
        'my_reaction': None,
        'is_mine': True,
        'comment_count': 0,
        'created_at': time.time()
    }
    DB['reels'].insert(0, reel)
    DB['comments'][reel['id']] = []
    
    return jsonify({'reel': reel})

@app.route('/api/reels/<reel_id>/view', methods=['POST'])
@token_required
def view_reel(reel_id):
    for reel in DB['reels']:
        if reel['id'] == reel_id:
            reel['view_count'] += 1
            return jsonify({'view_count': reel['view_count']})
    return jsonify({'error': 'Reel not found'}), 404

@app.route('/api/reels/<reel_id>/react', methods=['POST'])
@token_required
def react_to_reel(reel_id):
    data = request.get_json() or {}
    emoji = data.get('emoji')
    
    for reel in DB['reels']:
        if reel['id'] == reel_id:
            if emoji is None:
                if reel['my_reaction']:
                    reel['reaction_counts'][reel['my_reaction']] = max(0, reel['reaction_counts'].get(reel['my_reaction'], 0) - 1)
                reel['my_reaction'] = None
            else:
                if reel['my_reaction']:
                    reel['reaction_counts'][reel['my_reaction']] = max(0, reel['reaction_counts'].get(reel['my_reaction'], 0) - 1)
                reel['my_reaction'] = emoji
                reel['reaction_counts'][emoji] = reel['reaction_counts'].get(emoji, 0) + 1
            return jsonify({'reaction_counts': reel['reaction_counts']})
    
    return jsonify({'error': 'Reel not found'}), 404

@app.route('/api/reels/<reel_id>', methods=['DELETE'])
@token_required
def delete_reel(reel_id):
    for i, reel in enumerate(DB['reels']):
        if reel['id'] == reel_id:
            if reel['author_id'] != request.user_id:
                return jsonify({'error': 'Not your reel'}), 403
            try:
                file_path = reel['media_path'].lstrip('/')
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
            del DB['reels'][i]
            if reel_id in DB['comments']:
                del DB['comments'][reel_id]
            return jsonify({'success': True})
    return jsonify({'error': 'Reel not found'}), 404

@app.route('/api/reels/<reel_id>/comments', methods=['GET'])
@token_required
def get_reel_comments(reel_id):
    comments = DB['comments'].get(reel_id, [])
    return jsonify({'comments': comments})

@app.route('/api/reels/<reel_id>/comments', methods=['POST'])
@token_required
def add_reel_comment(reel_id):
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    parent_id = data.get('parent_id')
    
    if not content:
        return jsonify({'error': 'Comment content required'}), 400
    
    comment = {
        'id': generate_id(),
        'user_id': request.user_id,
        'author_name': request.user['username'],
        'author_avatar': request.user.get('avatar', ''),
        'content': content,
        'parent_id': parent_id,
        'created_at': time.time()
    }
    
    if reel_id not in DB['comments']:
        DB['comments'][reel_id] = []
    DB['comments'][reel_id].append(comment)
    
    for reel in DB['reels']:
        if reel['id'] == reel_id:
            reel['comment_count'] = len(DB['comments'][reel_id])
            break
    
    return jsonify({'comment': comment})

@app.route('/api/reels/comments/<comment_id>', methods=['DELETE'])
@token_required
def delete_reel_comment(comment_id):
    for reel_id, comments in DB['comments'].items():
        for i, comment in enumerate(comments):
            if comment['id'] == comment_id:
                if comment['user_id'] != request.user_id:
                    return jsonify({'error': 'Not your comment'}), 403
                del comments[i]
                for reel in DB['reels']:
                    if reel['id'] == reel_id:
                        reel['comment_count'] = len(comments)
                        break
                return jsonify({'success': True})
    return jsonify({'error': 'Comment not found'}), 404

# ===== SOCKET.IO EVENTS =====

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')

@socketio.on('auth')
def handle_auth(data):
    token = data.get('token')
    if not token:
        emit('error_msg', {'error': 'Token required'})
        return
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = payload['user_id']
        if user_id in DB['users']:
            request.user_id = user_id
            request.user = DB['users'][user_id]
            join_room(f'user_{user_id}')
            emit('auth_success', {'user_id': user_id})
            return
    except:
        pass
    
    emit('error_msg', {'error': 'Invalid token'})

@socketio.on('send_message')
def handle_send_message(data):
    if not hasattr(request, 'user_id'):
        emit('error_msg', {'error': 'Not authenticated'})
        return
    
    chat_type = data.get('chat_type')
    target = data.get('target')
    msg_type = data.get('msg_type', 'text')
    content = data.get('content', '')
    media_path = data.get('media_path', '')
    client_id = data.get('client_id')
    reply_to_id = data.get('reply_to_id')
    
    if not chat_type or not target:
        emit('error_msg', {'error': 'Missing chat_type or target'})
        return
    
    user = request.user
    user_id = user['id']
    
    if chat_type == 'dm':
        if target in user.get('blocked_ids', []):
            emit('error_msg', {'error': 'You blocked this user'})
            return
        other = DB['users'].get(target)
        if other and target in other.get('blocked_ids', []):
            emit('error_msg', {'error': 'You are blocked by this user'})
            return
    
    msg_id = generate_id()
    sender_name = user['username']
    sender_avatar = user.get('avatar', '')
    
    reply_to = None
    if reply_to_id:
        reply_msg = DB['messages'].get(reply_to_id)
        if reply_msg:
            reply_to = {
                'id': reply_msg['id'],
                'sender_name': reply_msg.get('sender_name', ''),
                'preview': reply_msg.get('preview', reply_msg.get('content', ''))[:50],
                'msg_type': reply_msg.get('msg_type', 'text')
            }
    
    message = {
        'id': msg_id,
        'chat_type': chat_type,
        'chat_id': target,
        'sender_id': user_id,
        'sender_name': sender_name,
        'sender_avatar': sender_avatar,
        'msg_type': msg_type,
        'content': content,
        'media_path': media_path,
        'timestamp': time.time(),
        'deleted': False,
        'edited': False,
        'reactions': [],
        'reply_to': reply_to,
        'forwarded_from': None,
        'client_id': client_id,
        'preview': content[:50] if msg_type == 'text' else ({'image': '📷 Photo', 'video': '🎬 Video', 'voice': '🎤 Voice message'}.get(msg_type, 'Message'))
    }
    
    DB['messages'][msg_id] = message
    
    if chat_type == 'dm':
        update_conversation(user_id, 'dm', target, message)
        update_conversation(target, 'dm', user_id, message)
    else:
        group = DB['groups'].get(target)
        if group:
            for member_id in group.get('members', []):
                update_conversation(member_id, 'group', target, message)
    
    formatted_msg = format_message(message)
    
    if chat_type == 'dm':
        emit('new_message', formatted_msg, room=f'user_{user_id}')
        emit('new_message', formatted_msg, room=f'user_{target}')
    else:
        group = DB['groups'].get(target)
        if group:
            for member_id in group.get('members', []):
                emit('new_message', formatted_msg, room=f'user_{member_id}')
    
    return formatted_msg

@socketio.on('edit_message')
def handle_edit_message(data):
    if not hasattr(request, 'user_id'):
        emit('error_msg', {'error': 'Not authenticated'})
        return
    
    message_id = data.get('message_id')
    content = data.get('content', '')
    
    msg = DB['messages'].get(message_id)
    if not msg:
        emit('error_msg', {'error': 'Message not found'})
        return
    
    if msg['sender_id'] != request.user_id:
        emit('error_msg', {'error': 'Not your message'})
        return
    
    msg['content'] = content
    msg['edited'] = True
    
    emit('message_edited', {'message_id': message_id, 'content': content}, room=f'user_{msg["sender_id"]}')
    if msg['chat_type'] == 'dm':
        emit('message_edited', {'message_id': message_id, 'content': content}, room=f'user_{msg["chat_id"]}')
    else:
        group = DB['groups'].get(msg['chat_id'])
        if group:
            for member_id in group.get('members', []):
                emit('message_edited', {'message_id': message_id, 'content': content}, room=f'user_{member_id}')

@socketio.on('delete_message')
def handle_delete_message(data):
    if not hasattr(request, 'user_id'):
        emit('error_msg', {'error': 'Not authenticated'})
        return
    
    message_id = data.get('message_id')
    msg = DB['messages'].get(message_id)
    if not msg:
        emit('error_msg', {'error': 'Message not found'})
        return
    
    if msg['sender_id'] != request.user_id:
        emit('error_msg', {'error': 'Not your message'})
        return
    
    msg['deleted'] = True
    
    emit('message_deleted', {'message_id': message_id}, room=f'user_{msg["sender_id"]}')
    if msg['chat_type'] == 'dm':
        emit('message_deleted', {'message_id': message_id}, room=f'user_{msg["chat_id"]}')
    else:
        group = DB['groups'].get(msg['chat_id'])
        if group:
            for member_id in group.get('members', []):
                emit('message_deleted', {'message_id': message_id}, room=f'user_{member_id}')

@socketio.on('react_message')
def handle_react_message(data):
    if not hasattr(request, 'user_id'):
        emit('error_msg', {'error': 'Not authenticated'})
        return
    
    message_id = data.get('message_id')
    emoji = data.get('emoji')
    
    msg = DB['messages'].get(message_id)
    if not msg or msg.get('deleted'):
        return
    
    reactions = [r for r in msg.get('reactions', []) if r['user_id'] != request.user_id]
    if emoji:
        reactions.append({'user_id': request.user_id, 'emoji': emoji})
    msg['reactions'] = reactions
    
    emit('message_reacted', {'message_id': message_id, 'user_id': request.user_id, 'emoji': emoji}, room=f'user_{msg["sender_id"]}')
    if msg['chat_type'] == 'dm':
        emit('message_reacted', {'message_id': message_id, 'user_id': request.user_id, 'emoji': emoji}, room=f'user_{msg["chat_id"]}')
    else:
        group = DB['groups'].get(msg['chat_id'])
        if group:
            for member_id in group.get('members', []):
                emit('message_reacted', {'message_id': message_id, 'user_id': request.user_id, 'emoji': emoji}, room=f'user_{member_id}')

@socketio.on('forward_message')
def handle_forward_message(data):
    if not hasattr(request, 'user_id'):
        emit('error_msg', {'error': 'Not authenticated'})
        return
    
    message_id = data.get('message_id')
    chat_type = data.get('chat_type')
    target = data.get('target')
    
    original_msg = DB['messages'].get(message_id)
    if not original_msg:
        emit('error_msg', {'error': 'Message not found'})
        return
    
    forwarded = original_msg.copy()
    forwarded['id'] = generate_id()
    forwarded['chat_type'] = chat_type
    forwarded['chat_id'] = target
    forwarded['sender_id'] = request.user_id
    forwarded['sender_name'] = request.user['username']
    forwarded['forwarded_from'] = {
        'id': original_msg['id'],
        'sender_name': original_msg.get('sender_name', '')
    }
    forwarded['timestamp'] = time.time()
    forwarded['reactions'] = []
    
    DB['messages'][forwarded['id']] = forwarded
    formatted_msg = format_message(forwarded)
    
    if chat_type == 'dm':
        emit('new_message', formatted_msg, room=f'user_{request.user_id}')
        emit('new_message', formatted_msg, room=f'user_{target}')
    else:
        group = DB['groups'].get(target)
        if group:
            for member_id in group.get('members', []):
                emit('new_message', formatted_msg, room=f'user_{member_id}')

@socketio.on('typing')
def handle_typing(data):
    if not hasattr(request, 'user_id'):
        return
    
    chat_type = data.get('chat_type')
    target = data.get('target')
    
    if chat_type == 'dm':
        emit('typing', {'from': request.user_id, 'chat_type': 'dm'}, room=f'user_{target}')
    else:
        group = DB['groups'].get(target)
        if group:
            for member_id in group.get('members', []):
                if member_id != request.user_id:
                    emit('typing', {'from': request.user_id, 'chat_type': 'group', 'group_id': target}, room=f'user_{member_id}')

@socketio.on('mark_read')
def handle_mark_read(data):
    if not hasattr(request, 'user_id'):
        return
    
    chat_type = data.get('chat_type')
    target = data.get('target')
    
    key = get_conversation_key(chat_type, target)
    if key in DB['conversations']:
        DB['conversations'][key]['unread'] = 0

# ===== CALL EVENTS =====

@socketio.on('call_offer')
def handle_call_offer(data):
    if not hasattr(request, 'user_id'):
        emit('error_msg', {'error': 'Not authenticated'})
        return
    
    target = data.get('target')
    offer = data.get('offer')
    call_type = data.get('call_type', 'audio')
    
    user = request.user
    emit('call_offer', {
        'from': user['id'],
        'from_name': user['username'],
        'from_avatar': user.get('avatar', ''),
        'offer': offer,
        'call_type': call_type
    }, room=f'user_{target}')

@socketio.on('call_answer')
def handle_call_answer(data):
    if not hasattr(request, 'user_id'):
        emit('error_msg', {'error': 'Not authenticated'})
        return
    
    target = data.get('target')
    answer = data.get('answer')
    emit('call_answer', {'from': request.user_id, 'answer': answer}, room=f'user_{target}')

@socketio.on('call_ice_candidate')
def handle_ice_candidate(data):
    if not hasattr(request, 'user_id'):
        return
    
    target = data.get('target')
    candidate = data.get('candidate')
    emit('call_ice_candidate', {'from': request.user_id, 'candidate': candidate}, room=f'user_{target}')

@socketio.on('call_reject')
def handle_call_reject(data):
    if not hasattr(request, 'user_id'):
        return
    
    target = data.get('target')
    reason = data.get('reason', 'declined')
    emit('call_reject', {'from': request.user_id, 'reason': reason}, room=f'user_{target}')

@socketio.on('call_end')
def handle_call_end(data):
    if not hasattr(request, 'user_id'):
        return
    
    target = data.get('target')
    emit('call_end', {'from': request.user_id}, room=f'user_{target}')

# ===== ERROR HANDLING =====

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ===== RUN SERVER =====

if __name__ == '__main__':
    print(f"🚀 HM Chat Server running on port {PORT}")
    print(f"📡 Socket.IO enabled")
    print(f"🔑 JWT Secret: {JWT_SECRET[:8]}...")
    print(f"📁 Upload folder: {UPLOAD_FOLDER}")
    socketio.run(app, host='0.0.0.0', port=PORT, debug=True, allow_unsafe_werkzeug=True)
