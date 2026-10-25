from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt
import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

db = SQLAlchemy(app)

# ---------- 数据库模型 ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)

# ---------- 工具函数 ----------
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash)

def generate_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# JWT 验证中间件
def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        data = decode_token(token)
        if not data:
            return jsonify({'error': 'Invalid or expired token'}), 403
        return f(current_user=data, *args, **kwargs)
    return decorated

# XSS 防护：转义输出
def escape_html(text):
    if not isinstance(text, str):
        return text
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

# ---------- API 接口 ----------

# 1. 注册（方便测试用）
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'User already exists'}), 400
    new_user = User(username=username, password_hash=hash_password(password))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created', 'user_id': new_user.id}), 201

# 2. 登录 — POST /auth/login
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not check_password(password, user.password_hash):
        return jsonify({'error': 'Invalid username or password'}), 401
    token = generate_token(user.id, user.username)
    return jsonify({'token': token})

# 3. 获取数据 — GET /api/data（仅认证用户）
@app.route('/api/data', methods=['GET'])
@token_required
def get_data(current_user):
    posts = Post.query.filter_by(user_id=current_user['user_id']).all()
    result = []
    for p in posts:
        result.append({
            'id': p.id,
            'title': escape_html(p.title),   # XSS 防护
            'content': escape_html(p.content)  # XSS 防护
        })
    return jsonify(result)

# 4. 自定义第三个接口 — 创建帖子
@app.route('/api/posts', methods=['POST'])
@token_required
def create_post(current_user):
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    if not title or not content:
        return jsonify({'error': 'title and content required'}), 400
    new_post = Post(user_id=current_user['user_id'], title=title, content=content)
    db.session.add(new_post)
    db.session.commit()
    return jsonify({'message': 'Post created', 'post_id': new_post.id}), 201

# ---------- 启动 ----------
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # debug 模式仅通过环境变量开启（FLASK_DEBUG=1），生产/扫描默认关闭
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, port=5000)
