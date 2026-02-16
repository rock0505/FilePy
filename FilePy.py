#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FilePy v0.2.0 - 轻量级文件服务器
使用Python + FastAPI + SQLite实现
安全增强版本 - 支持速率限制、文件类型验证、强制密码修改等
"""

import os
import sys
import sqlite3
import hashlib
import json
import argparse
import logging
import secrets
import uuid
from datetime import datetime
from typing import Optional, List, Dict
from pathlib import Path
from functools import lru_cache

# 配置文件支持
import configparser

from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from passlib.context import CryptContext

# ============================================================================
# 配置文件管理
# ============================================================================

def load_config():
    """从 config.ini 加载配置"""
    config = configparser.ConfigParser()
    config_path = Path(__file__).parent / 'config.ini'

    if config_path.exists():
        config.read(config_path, encoding='utf-8')
        print(f"从 {config_path} 加载配置")
    else:
        print(f"配置文件 {config_path} 不存在，使用默认配置")
        # 创建默认配置文件
        config['server'] = {
            'host': '0.0.0.0',
            'port': '1966'
        }
        config['security'] = {
            'secret_key': 'change-this-secret-key-in-production'
        }
        config['cors'] = {
            'allow_origins': 'http://localhost:1966,http://127.0.0.1:1966'
        }
        with open(config_path, 'w', encoding='utf-8') as f:
            config.write(f)
        print(f"创建默认配置文件: {config_path}")

    return config

def get_config(key: str, section: str = 'server', fallback: str = ''):
    """获取配置值"""
    config = load_config()
    try:
        return config.get(section, key, fallback=fallback)
    except:
        return fallback

# ============================================================================
# 全局配置
# ============================================================================

config = load_config()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# 安全配置
# ============================================================================

# 密码哈希上下文（使用 bcrypt）
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 速率限制器配置
limiter = Limiter(key_func=get_remote_address)
# 默认速率限制：每分钟 60 次请求
DEFAULT_RATE_LIMIT = "60/minute"
# 登录速率限制：每分钟 5 次尝试
LOGIN_RATE_LIMIT = "5/minute"

# 允许的文件类型（MIME 类型白名单）
ALLOWED_MIME_TYPES = {
    # 图片
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/svg+xml',
    # 文档
    'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain', 'text/csv', 'text/markdown',
    # 压缩文件
    'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
    'application/gzip', 'application/x-tar',
    # 媒体
    'audio/mpeg', 'audio/wav', 'audio/ogg', 'video/mp4', 'video/mpeg', 'video/webm',
    # 其他
    'application/json', 'application/xml', 'text/xml',
}

# 危险文件扩展名黑名单
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
    '.sh', '.bash', '.ps1', '.app', '.deb', '.rpm', '.dmg', '.pkg',
}

# 从配置文件或环境变量读取配置
# 优先级：config.ini > 环境变量 > 默认值
def get_config_value(key: str, section: str = 'security', default: str = '') -> str:
    """获取配置值，优先级：config.ini > 环境变量 > 默认值"""
    # 先尝试从 config.ini 读取
    try:
        value = config.get(section, key, fallback='')
        if value:
            return value
    except:
        pass

    # 再尝试从环境变量读取
    env_key = f"FILEPY_{key.upper()}"
    env_value = os.getenv(env_key)
    if env_value:
        return env_value

    return default

# ============================================================================
# 应用配置
# ============================================================================

# 从配置读取 SECRET_KEY
SECRET_KEY = get_config_value('secret_key', section='security', default='change-this-default-secret-key')
if SECRET_KEY == 'change-this-default-secret-key':
    logger.warning("警告: 使用默认 SECRET_KEY，请在 config.ini 中设置 secret_key")

# CORS 允许的来源
ALLOWED_ORIGINS = get_config_value('allow_origins', section='cors', default='http://localhost:1966,http://127.0.0.1:1966').split(',')
# 过滤空字符串
ALLOWED_ORIGINS = [origin for origin in ALLOWED_ORIGINS if origin.strip()]

# 数据库初始化
def init_database():
    """初始化数据库表结构"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 创建用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            is_admin BOOLEAN DEFAULT FALSE,
            force_password_change BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 创建组表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 创建用户组关联表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_groups (
            user_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (user_id, group_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    ''')

    # 创建权限表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    ''')

    # 创建文件表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            size INTEGER,
            mime_type TEXT,
            owner_id INTEGER,
            group_id INTEGER,
            permissions TEXT,  -- JSON格式存储权限
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL
        )
    ''')

    # 创建日志表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    # 创建配置表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            description TEXT
        )
    ''')

    # 创建配额表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quotas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            quota_limit INTEGER,  -- 配额限制（字节）
            quota_used INTEGER DEFAULT 0,  -- 已使用配额（字节）
            warning_threshold INTEGER DEFAULT 80,  -- 预警阈值（百分比）
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # 创建配额使用记录表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quota_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_id INTEGER,
            action TEXT,  -- upload, delete
            size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL
        )
    ''')

    # ============================================================================
    # 数据库迁移：为旧版本数据库添加新列
    # ============================================================================

    # 检查并添加 force_password_change 列到 users 表
    try:
        cursor.execute("SELECT force_password_change FROM users LIMIT 1")
    except sqlite3.OperationalError:
        # 列不存在，添加它
        cursor.execute("ALTER TABLE users ADD COLUMN force_password_change BOOLEAN DEFAULT FALSE")
        print(f"从 {config_path} 加载配置")

    conn.commit()

    # 插入默认权限
    default_permissions = [
        ('read', '读取权限'),
        ('write', '写入权限'),
        ('execute', '执行权限'),
        ('delete', '删除权限')
    ]

    for perm_name, perm_desc in default_permissions:
        cursor.execute(
            'INSERT OR IGNORE INTO permissions (name, description) VALUES (?, ?)',
            (perm_name, perm_desc)
        )

    # 创建默认管理员用户 (密码为admin123，首次登录后需要强制修改)
    # 使用 bcrypt 进行密码哈希
    password_hash = pwd_context.hash('admin123')
    cursor.execute(
        'INSERT OR IGNORE INTO users (username, password_hash, is_admin, force_password_change) VALUES (?, ?, ?, ?)',
        ('admin', password_hash, True, True)
    )

    # 如果数据库中已有管理员但没有 force_password_change 字段，更新它
    cursor.execute('''
        UPDATE users SET force_password_change = 1
        WHERE username = 'admin' AND force_password_change IS NULL
    ''')

    # 插入默认配置项
    default_configs = [
        ('max_upload_size', '104857600', '最大上传文件大小(字节)，默认100MB'),
        ('allow_registration', 'false', '是否允许用户注册，默认false')
    ]

    for config_key, config_value, config_desc in default_configs:
        cursor.execute(
            'INSERT OR IGNORE INTO config (key, value, description) VALUES (?, ?, ?)',
            (config_key, config_value, config_desc)
        )

    conn.commit()
    conn.close()
    logger.info("数据库初始化完成")

# 数据模型
class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None

class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class FileInfo(BaseModel):
    name: str
    path: str
    size: Optional[int] = None
    mime_type: Optional[str] = None

class FolderCreate(BaseModel):
    name: str
    path: str = "/"

class FileRename(BaseModel):
    old_path: str
    new_name: str

class BatchDelete(BaseModel):
    paths: List[str]

class BatchRename(BaseModel):
    items: List[Dict[str, str]]  # [{"old_path": "...", "new_name": "..."}]

class SearchQuery(BaseModel):
    name: Optional[str] = None
    min_size: Optional[int] = None
    max_size: Optional[int] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    path: str = "/"

class QuotaSet(BaseModel):
    user_id: int
    quota_limit: int
    warning_threshold: Optional[int] = 80

class QuotaInfo(BaseModel):
    quota_limit: int
    quota_used: int
    warning_threshold: int

class TokenData(BaseModel):
    user_id: int
    username: str
    is_admin: bool

class ConfigItem(BaseModel):
    key: str
    value: str
    description: Optional[str] = None

# ACL权限模型
class FilePermission(BaseModel):
    user_id: Optional[int] = None
    group_id: Optional[int] = None
    permission: str  # read, write, execute, delete

# 安全相关
security = HTTPBearer()

# JWT secret key
SECRET_KEY = os.getenv("FILEPY_SECRET_KEY", "super-secret-key")  # 理想情况下应从 env / config 中读取

# JWT 相关导入
from jose import jwt, JWTError
from datetime import datetime, timedelta


# FastAPI应用
app = FastAPI(
    title="FilePy 文件服务器",
    description="一个轻量级的文件服务器，支持权限控制和Web界面",
    version="1.0.1"
)

# 设置速率限制器
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS配置（使用环境变量配置的允许来源）
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 安全响应头中间件
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """添加安全响应头"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    return response

# 认证依赖
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), request: Request = None) -> TokenData:
    """验证JWT令牌并返回用户信息"""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id: int = payload.get("user_id")
        username: str = payload.get("username")
        is_admin: bool = payload.get("is_admin")
        if user_id is None or username is None:
            raise JWTError
        # 记录 IP 地址
        ip = None
        if request and request.client:
            ip = request.client.host
        # 这里可以在 log_action 中记录 ip，可选
        return TokenData(user_id=user_id, username=username, is_admin=is_admin)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌",
            headers={"WWW-Authenticate": "Bearer"},
        )

# 工具函数
def hash_password(password: str) -> str:
    """对密码进行哈希处理（使用 bcrypt）"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码（支持 bcrypt 和旧版 SHA256 以保持向后兼容）"""
    # 首先尝试使用 bcrypt 验证
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except:
        # 如果 bcrypt 验证失败，尝试使用旧版 SHA256 验证（向后兼容）
        return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password

def log_action(user_id: int, action: str, resource_type: str, resource_id: int, details: str = "", ip: str = ""):
    """记录操作日志"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO logs (user_id, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, action, resource_type, resource_id, details, ip)
    )
    conn.commit()
    conn.close()

def check_file_permission(file_id: int, user_id: int, permission: str) -> bool:
    """检查用户对文件的权限"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 获取文件信息
    cursor.execute('SELECT owner_id, group_id, permissions FROM files WHERE id = ?', (file_id,))
    file_record = cursor.fetchone()
    if not file_record:
        conn.close()
        return False

    owner_id, group_id, permissions_str = file_record

    # 如果是文件所有者，允许所有操作
    if owner_id == user_id:
        conn.close()
        return True

    # 如果是管理员，允许所有操作
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user_record = cursor.fetchone()
    if user_record and user_record[0]:
        conn.close()
        return True

    # 解析权限
    try:
        permissions = json.loads(permissions_str) if permissions_str else []
    except:
        permissions = []

    # 检查用户特定权限
    for perm in permissions:
        if perm.get('user_id') == user_id and perm.get('permission') == permission:
            conn.close()
            return True

    # 检查组权限
    if group_id:
        # 获取用户所属的所有组
        cursor.execute('SELECT group_id FROM user_groups WHERE user_id = ?', (user_id,))
        user_groups = [row[0] for row in cursor.fetchall()]

        # 检查组权限
        for perm in permissions:
            if perm.get('group_id') in user_groups and perm.get('permission') == permission:
                conn.close()
                return True

    conn.close()
    return False

def set_file_permissions(file_id: int, permissions: List[Dict]) -> bool:
    """设置文件权限"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    try:
        permissions_str = json.dumps(permissions)
        cursor.execute('UPDATE files SET permissions = ? WHERE id = ?', (permissions_str, file_id))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def get_file_permissions(file_id: int) -> List[Dict]:
    """获取文件权限"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    cursor.execute('SELECT permissions FROM files WHERE id = ?', (file_id,))
    record = cursor.fetchone()
    conn.close()

    if record and record[0]:
        try:
            return json.loads(record[0])
        except:
            return []
    return []

def get_db_config(key: str, default_value: str = "") -> str:
    """从数据库获取配置值"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM config WHERE key = ?', (key,))
    record = cursor.fetchone()
    conn.close()

    if record:
        return record[0]
    return default_value

def update_user_quota(user_id: int, file_size: int, action: str = "upload"):
    """更新用户配额使用情况"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 获取用户配额信息
    cursor.execute('SELECT quota_limit, quota_used FROM quotas WHERE user_id = ?', (user_id,))
    quota_record = cursor.fetchone()

    if quota_record:
        quota_limit, quota_used = quota_record
        if action == "upload":
            new_quota_used = quota_used + file_size
        else:  # delete
            new_quota_used = max(0, quota_used - file_size)

        cursor.execute('UPDATE quotas SET quota_used = ?, last_updated = CURRENT_TIMESTAMP WHERE user_id = ?',
                     (new_quota_used, user_id))
    else:
        # 如果没有配额记录，创建一个（默认无限配额）
        cursor.execute('INSERT INTO quotas (user_id, quota_limit, quota_used) VALUES (?, ?, ?)',
                     (user_id, 0, file_size if action == "upload" else 0))

    conn.commit()
    conn.close()

def check_quota_warning(user_id: int) -> dict:
    """检查用户配额使用情况和预警"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    cursor.execute('SELECT quota_limit, quota_used, warning_threshold FROM quotas WHERE user_id = ?', (user_id,))
    quota_record = cursor.fetchone()
    conn.close()

    if not quota_record:
        return {"warning": False, "message": "无配额限制"}

    quota_limit, quota_used, warning_threshold = quota_record

    if quota_limit == 0:
        return {"warning": False, "message": "无配额限制"}

    usage_percent = (quota_used / quota_limit) * 100

    if usage_percent >= 100:
        return {
            "warning": True,
            "level": "critical",
            "message": f"配额已用完 ({usage_percent:.1f}%)",
            "quota_used": quota_used,
            "quota_limit": quota_limit,
            "usage_percent": usage_percent
        }
    elif usage_percent >= warning_threshold:
        return {
            "warning": True,
            "level": "warning",
            "message": f"配额使用超过预警阈值 ({usage_percent:.1f}%)",
            "quota_used": quota_used,
            "quota_limit": quota_limit,
            "usage_percent": usage_percent
        }

    return {
        "warning": False,
        "message": f"配额使用正常 ({usage_percent:.1f}%)",
        "quota_used": quota_used,
        "quota_limit": quota_limit,
        "usage_percent": usage_percent
    }

def get_disk_usage() -> dict:
    """获取磁盘使用情况"""
    import shutil
    storage_path = Path("storage").absolute()
    total, used, free = shutil.disk_usage(storage_path)

    return {
        "total": total,
        "used": used,
        "free": free,
        "usage_percent": (used / total) * 100
    }

# API路由

@app.post("/auth/login", summary="用户登录")
@limiter.limit(LOGIN_RATE_LIMIT)
async def login(request: Request, user_data: UserLogin):
    """用户登录接口（带速率限制）"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, username, password_hash, is_admin, force_password_change FROM users WHERE username = ?',
        (user_data.username,)
    )
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(user_data.password, user[2]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )

    # 生成 JWT
    to_encode = {
        "user_id": user[0],
        "username": user[1],
        "is_admin": bool(user[3]),
        "exp": datetime.utcnow() + timedelta(minutes=60)
    }
    token = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

    # 检查是否需要强制修改密码
    force_password_change = bool(user[4]) if len(user) > 4 else False

    return {
        "access_token": token,
        "token_type": "bearer",
        "force_password_change": force_password_change
    }

@app.post("/auth/register", summary="用户注册")
async def register(user_data: UserCreate, current_user: TokenData = Depends(get_current_user)):
    """用户注册接口（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以创建用户"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            (user_data.username, hash_password(user_data.password), user_data.email)
        )
        conn.commit()
        user_id = cursor.lastrowid
        log_action(current_user.user_id, "create_user", "user", user_id, f"创建用户 {user_data.username}")
        return {"id": user_id, "username": user_data.username, "email": user_data.email}
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户名已存在"
        )
    finally:
        conn.close()

@app.post("/auth/change-password", summary="修改密码")
async def change_password(
    password_data: PasswordChange,
    current_user: TokenData = Depends(get_current_user)
):
    """修改当前用户密码"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    try:
        # 获取当前用户信息
        cursor.execute(
            'SELECT id, password_hash FROM users WHERE id = ?',
            (current_user.user_id,)
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="用户不存在"
            )

        # 验证旧密码
        if not verify_password(password_data.old_password, user[1]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="原密码错误"
            )

        # 新密码长度验证
        if len(password_data.new_password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="新密码长度不能少于6位"
            )

        # 更新密码
        new_password_hash = hash_password(password_data.new_password)
        cursor.execute(
            'UPDATE users SET password_hash = ?, force_password_change = 0 WHERE id = ?',
            (new_password_hash, current_user.user_id)
        )
        conn.commit()

        log_action(current_user.user_id, "change_password", "user", current_user.user_id, "修改密码")

        return {"message": "密码修改成功"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"修改密码失败: {e}")
        raise HTTPException(status_code=500, detail="修改密码失败")
    finally:
        conn.close()

@app.post("/files/search", summary="高级搜索文件")
async def search_files(
    query: SearchQuery,
    current_user: TokenData = Depends(get_current_user)
):
    """高级搜索文件（支持按名称、大小、时间搜索）"""
    try:
        storage_path = Path("storage")
        search_path = storage_path / query.path.lstrip("/")

        if not search_path.exists():
            raise HTTPException(status_code=404, detail="搜索路径不存在")

        results = []

        # 递归搜索所有文件
        for item in search_path.rglob("*"):
            if item.is_file() or item.is_dir():
                stat = item.stat()

                # 检查名称过滤
                if query.name:
                    if query.name.lower() not in item.name.lower():
                        continue

                # 检查大小过滤
                if query.min_size is not None or query.max_size is not None:
                    if item.is_file():
                        size = stat.st_size
                        if query.min_size is not None and size < query.min_size:
                            continue
                        if query.max_size is not None and size > query.max_size:
                            continue
                    else:
                        # 目录没有大小限制
                        continue

                # 检查日期过滤
                if query.start_date or query.end_date:
                    mtime = datetime.fromtimestamp(stat.st_mtime)
                    if query.start_date:
                        start_dt = datetime.fromisoformat(query.start_date)
                        if mtime < start_dt:
                            continue
                    if query.end_date:
                        end_dt = datetime.fromisoformat(query.end_date)
                        if mtime > end_dt:
                            continue

                results.append({
                    "name": item.name,
                    "path": str(item.relative_to(storage_path)),
                    "is_dir": item.is_dir(),
                    "size": stat.st_size if item.is_file() else None,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })

        log_action(current_user.user_id, "search_files", "directory", 0,
                  f"搜索文件: 名称={query.name}, 大小范围={query.min_size}-{query.max_size}, 日期范围={query.start_date}-{query.end_date}")

        return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"搜索文件失败: {e}")
        raise HTTPException(status_code=500, detail="搜索文件失败")

@app.get("/files", summary="获取文件列表")
async def list_files(
    path: str = "/",
    current_user: TokenData = Depends(get_current_user)
):
    """获取文件列表"""
    # 确保文件存储目录存在
    storage_path = Path("storage")
    storage_path.mkdir(exist_ok=True)

    # 获取目录下的文件
    try:
        full_path = storage_path / path.lstrip("/")
        if not full_path.exists():
            raise HTTPException(status_code=404, detail="路径不存在")

        if full_path.is_file():
            raise HTTPException(status_code=400, detail="路径不是目录")

        items = []
        for item in full_path.iterdir():
            stat = item.stat()
            items.append({
                "name": item.name,
                "path": str(item.relative_to(storage_path)),
                "is_dir": item.is_dir(),
                "size": stat.st_size if item.is_file() else None,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })

        log_action(current_user.user_id, "list_files", "directory", 0, f"查看目录 {path}")
        return items
    except Exception as e:
        logger.error(f"获取文件列表失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")

@app.post("/files/mkdir", summary="创建目录")
async def create_directory(
    folder_data: FolderCreate,
    current_user: TokenData = Depends(get_current_user)
):
    """创建新目录"""
    try:
        storage_path = Path("storage")
        target_dir = storage_path / folder_data.path.lstrip("/")
        target_dir.mkdir(parents=True, exist_ok=True)

        new_folder = target_dir / folder_data.name

        # 检查是否已存在
        if new_folder.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="目录已存在"
            )

        # 创建目录
        new_folder.mkdir()

        log_action(current_user.user_id, "create_directory", "directory", 0,
                  f"创建目录 {folder_data.name} 在 {folder_data.path}")

        return {
            "message": "目录创建成功",
            "name": folder_data.name,
            "path": str(new_folder.relative_to(storage_path))
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建目录失败: {e}")
        raise HTTPException(status_code=500, detail="创建目录失败")

@app.post("/files/upload", summary="上传文件")
@limiter.limit(DEFAULT_RATE_LIMIT)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    path: str = Form("/"),
    current_user: TokenData = Depends(get_current_user)
):
    """上传文件（带文件类型验证和路径穿越防护）"""
    try:
        # 验证文件名
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="文件名不能为空"
            )

        # 检查危险文件扩展名
        file_ext = Path(file.filename).suffix.lower()
        if file_ext in DANGEROUS_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"不允许上传 {file_ext} 类型的文件"
            )

        # 检查文件大小限制
        content = await file.read()
        file_size = len(content)

        # 获取最大上传大小配置
        max_upload_size_str = get_config_value('max_size', section='upload', default='104857600')  # 默认100MB
        try:
            max_upload_size = int(max_upload_size_str)
        except ValueError:
            max_upload_size = 104857600  # 默认100MB

        if file_size > max_upload_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"文件大小超过限制 ({max_upload_size} bytes)"
            )

        # 检查用户配额
        quota_check = check_quota_warning(current_user.user_id)
        if quota_check["warning"] and quota_check["level"] == "critical":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=quota_check["message"]
            )

        # 验证 MIME 类型
        if file.content_type and file.content_type not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"不允许上传 {file.content_type} 类型的文件"
            )

        # 重置文件指针
        await file.seek(0)

        # 确保存储目录存在
        storage_path = Path("storage").resolve()
        storage_path.mkdir(exist_ok=True)

        # 构建完整路径（防止路径穿越攻击）
        # 清理路径，移除 .. 和其他危险字符
        clean_path = path.lstrip("/").replace("..", "").replace("\\", "/")
        target_dir = (storage_path / clean_path).resolve()

        # 确保目标路径在 storage 目录内
        if not str(target_dir).startswith(str(storage_path)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="非法的路径访问"
            )

        target_dir.mkdir(parents=True, exist_ok=True)

        file_path = target_dir / file.filename

        # 再次验证最终文件路径在 storage 目录内
        if not str(file_path.resolve()).startswith(str(storage_path)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="非法的文件路径"
            )

        # 保存文件
        with open(file_path, "wb") as buffer:
            buffer.write(content)

        # 保存文件信息到数据库
        conn = sqlite3.connect('filepy.db')
        cursor = conn.cursor()
        stat = file_path.stat()

        cursor.execute(
            'INSERT INTO files (name, path, size, mime_type, owner_id) VALUES (?, ?, ?, ?, ?)',
            (file.filename, str(file_path), stat.st_size, file.content_type, current_user.user_id)
        )
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()

        log_action(current_user.user_id, "upload_file", "file", file_id, f"上传文件 {file.filename} 到 {path} (大小: {file_size} bytes)")

        # 更新用户配额使用情况
        update_user_quota(current_user.user_id, file_size, "upload")

        # 记录配额使用
        conn = sqlite3.connect('filepy.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO quota_usage (user_id, file_id, action, size) VALUES (?, ?, ?, ?)',
                     (current_user.user_id, file_id, "upload", file_size))
        conn.commit()
        conn.close()

        # 检查配额预警
        quota_warning = check_quota_warning(current_user.user_id)
        return {
            "id": file_id,
            "filename": file.filename,
            "size": stat.st_size,
            "content_type": file.content_type,
            "quota_warning": quota_warning
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"文件上传失败: {e}")
        raise HTTPException(status_code=500, detail="文件上传失败")

@app.get("/files/download/{file_path:path}", summary="下载文件")
async def download_file(
    file_path: str,
    current_user: TokenData = Depends(get_current_user)
):
    """下载文件"""
    try:
        storage_path = Path("storage")
        full_path = storage_path / file_path

        if not full_path.exists() or full_path.is_dir():
            raise HTTPException(status_code=404, detail="文件不存在")

        # 记录日志
        conn = sqlite3.connect('filepy.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM files WHERE path = ?', (str(full_path),))
        file_record = cursor.fetchone()
        file_id = file_record[0] if file_record else 0
        conn.close()

        log_action(current_user.user_id, "download_file", "file", file_id, f"下载文件 {file_path}")

        return FileResponse(str(full_path))
    except Exception as e:
        logger.error(f"文件下载失败: {e}")
        raise HTTPException(status_code=500, detail="文件下载失败")

@app.put("/files/rename", summary="重命名文件或目录")
async def rename_file(
    rename_data: FileRename,
    current_user: TokenData = Depends(get_current_user)
):
    """重命名文件或目录"""
    try:
        storage_path = Path("storage")
        old_path = storage_path / rename_data.old_path.lstrip("/")

        if not old_path.exists():
            raise HTTPException(status_code=404, detail="文件或目录不存在")

        # 构建新路径
        parent_dir = old_path.parent
        new_path = parent_dir / rename_data.new_name

        # 检查新路径是否已存在
        if new_path.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="目标名称已存在"
            )

        # 重命名
        old_path.rename(new_path)

        # 更新数据库中的文件记录（如果是文件）
        conn = sqlite3.connect('filepy.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM files WHERE path = ?', (str(old_path),))
        file_record = cursor.fetchone()
        file_id = file_record[0] if file_record else 0

        if file_id:
            cursor.execute('UPDATE files SET path = ?, name = ? WHERE id = ?',
                         (str(new_path), rename_data.new_name, file_id))
            conn.commit()
        conn.close()

        log_action(current_user.user_id, "rename_file", "file", file_id,
                  f"重命名 {rename_data.old_path} 为 {rename_data.new_name}")

        return {"message": "重命名成功"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"重命名失败: {e}")
        raise HTTPException(status_code=500, detail="重命名失败")

@app.delete("/files/batch", summary="批量删除文件")
async def batch_delete_files(
    batch_data: BatchDelete,
    current_user: TokenData = Depends(get_current_user)
):
    """批量删除文件或目录"""
    storage_path = Path("storage")
    success_count = 0
    failed_items = []

    for file_path in batch_data.paths:
        try:
            full_path = storage_path / file_path.lstrip("/")

            if not full_path.exists():
                failed_items.append({"path": file_path, "error": "文件不存在"})
                continue

            # 从数据库删除文件记录
            conn = sqlite3.connect('filepy.db')
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM files WHERE path = ?', (str(full_path),))
            file_record = cursor.fetchone()
            file_id = file_record[0] if file_record else 0

            if file_id:
                cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
                conn.commit()
            conn.close()

            # 删除物理文件
            if full_path.is_file():
                full_path.unlink()
            elif full_path.is_dir():
                import shutil
                shutil.rmtree(full_path)

            success_count += 1
        except Exception as e:
            failed_items.append({"path": file_path, "error": str(e)})

    log_action(current_user.user_id, "batch_delete", "files", 0,
              f"批量删除 {success_count} 个文件")

    return {
        "message": f"成功删除 {success_count} 个文件",
        "success_count": success_count,
        "failed_count": len(failed_items),
        "failed_items": failed_items
    }

@app.put("/files/batch/rename", summary="批量重命名文件")
async def batch_rename_files(
    batch_data: BatchRename,
    current_user: TokenData = Depends(get_current_user)
):
    """批量重命名文件或目录"""
    storage_path = Path("storage")
    success_count = 0
    failed_items = []

    for item in batch_data.items:
        try:
            old_path = storage_path / item["old_path"].lstrip("/")
            new_name = item["new_name"]

            if not old_path.exists():
                failed_items.append({"path": item["old_path"], "error": "文件不存在"})
                continue

            # 构建新路径
            parent_dir = old_path.parent
            new_path = parent_dir / new_name

            # 检查新路径是否已存在
            if new_path.exists():
                failed_items.append({"path": item["old_path"], "error": "目标名称已存在"})
                continue

            # 重命名
            old_path.rename(new_path)

            # 更新数据库记录
            conn = sqlite3.connect('filepy.db')
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM files WHERE path = ?', (str(old_path),))
            file_record = cursor.fetchone()
            file_id = file_record[0] if file_record else 0

            if file_id:
                cursor.execute('UPDATE files SET path = ?, name = ? WHERE id = ?',
                             (str(new_path), new_name, file_id))
                conn.commit()
            conn.close()

            success_count += 1
        except Exception as e:
            failed_items.append({"path": item["old_path"], "error": str(e)})

    log_action(current_user.user_id, "batch_rename", "files", 0,
              f"批量重命名 {success_count} 个文件")

    return {
        "message": f"成功重命名 {success_count} 个文件",
        "success_count": success_count,
        "failed_count": len(failed_items),
        "failed_items": failed_items
    }

@app.delete("/files/{file_path:path}", summary="删除文件")
async def delete_file(
    file_path: str,
    current_user: TokenData = Depends(get_current_user)
):
    """删除文件"""
    try:
        storage_path = Path("storage")
        full_path = storage_path / file_path

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="文件不存在")

        # 从数据库删除文件记录
        conn = sqlite3.connect('filepy.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, owner_id, size FROM files WHERE path = ?', (str(full_path),))
        file_record = cursor.fetchone()
        file_id = file_record[0] if file_record else 0
        file_owner = file_record[1] if file_record else 0
        file_size = file_record[2] if file_record else 0

        if file_id:
            cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
            conn.commit()
        conn.close()

        # 更新文件所有者的配额使用情况
        if file_owner and file_size:
            update_user_quota(file_owner, file_size, "delete")

            # 记录配额使用
            conn = sqlite3.connect('filepy.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO quota_usage (user_id, file_id, action, size) VALUES (?, ?, ?, ?)',
                         (file_owner, file_id, "delete", file_size))
            conn.commit()
            conn.close()

        # 删除物理文件
        if full_path.is_file():
            full_path.unlink()
        elif full_path.is_dir():
            import shutil
            shutil.rmtree(full_path)

        log_action(current_user.user_id, "delete_file", "file", file_id, f"删除文件 {file_path}")

        return {"message": "文件删除成功"}
    except Exception as e:
        logger.error(f"文件删除失败: {e}")
        raise HTTPException(status_code=500, detail="文件删除失败")

# ACL权限管理API
@app.get("/files/{file_id}/permissions", summary="获取文件权限")
async def get_file_permissions_api(
    file_id: int,
    current_user: TokenData = Depends(get_current_user)
):
    """获取文件权限列表"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查文件是否存在
    cursor.execute('SELECT id, owner_id FROM files WHERE id = ?', (file_id,))
    file_record = cursor.fetchone()
    if not file_record:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="文件不存在"
        )

    # 检查用户是否有权限查看权限（文件所有者或管理员）
    if file_record[1] != current_user.user_id and not current_user.is_admin:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="没有权限查看此文件的权限信息"
        )

    conn.close()
    permissions = get_file_permissions(file_id)
    return permissions

@app.post("/files/{file_id}/permissions", summary="设置文件权限")
async def set_file_permissions_api(
    file_id: int,
    permissions: List[FilePermission],
    current_user: TokenData = Depends(get_current_user)
):
    """设置文件权限"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查文件是否存在
    cursor.execute('SELECT id, owner_id FROM files WHERE id = ?', (file_id,))
    file_record = cursor.fetchone()
    if not file_record:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="文件不存在"
        )

    # 检查用户是否有权限设置权限（文件所有者或管理员）
    if file_record[1] != current_user.user_id and not current_user.is_admin:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="没有权限设置此文件的权限"
        )

    conn.close()

    # 转换权限格式
    permissions_dict = []
    for perm in permissions:
        permissions_dict.append({
            "user_id": perm.user_id,
            "group_id": perm.group_id,
            "permission": perm.permission
        })

    if set_file_permissions(file_id, permissions_dict):
        log_action(current_user.user_id, "set_file_permissions", "file", file_id, "设置文件权限")
        return {"message": "文件权限设置成功"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="设置文件权限失败"
        )

@app.get("/quota", summary="获取当前用户配额信息")
async def get_user_quota(current_user: TokenData = Depends(get_current_user)):
    """获取当前用户的配额使用情况"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    cursor.execute('SELECT quota_limit, quota_used, warning_threshold FROM quotas WHERE user_id = ?',
                 (current_user.user_id,))
    quota_record = cursor.fetchone()

    if not quota_record:
        # 创建默认配额记录（无限配额）
        cursor.execute('INSERT INTO quotas (user_id, quota_limit, quota_used) VALUES (?, ?, ?)',
                     (current_user.user_id, 0, 0))
        conn.commit()
        quota_limit = 0
        quota_used = 0
        warning_threshold = 80
    else:
        quota_limit, quota_used, warning_threshold = quota_record

    conn.close()

    # 获取磁盘使用情况
    disk_usage = get_disk_usage()

    quota_info = {
        "quota_limit": quota_limit,
        "quota_used": quota_used,
        "warning_threshold": warning_threshold,
        "usage_percent": (quota_used / quota_limit * 100) if quota_limit > 0 else 0,
        "unlimited": quota_limit == 0
    }

    quota_warning = check_quota_warning(current_user.user_id)

    return {
        **quota_info,
        "warning": quota_warning,
        "disk_usage": disk_usage
    }

@app.get("/quota/users/{user_id}", summary="获取指定用户配额信息")
async def get_user_quota_by_id(
    user_id: int,
    current_user: TokenData = Depends(get_current_user)
):
    """获取指定用户的配额信息（仅管理员）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以查看其他用户的配额信息"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    cursor.execute('SELECT quota_limit, quota_used, warning_threshold FROM quotas WHERE user_id = ?',
                 (user_id,))
    quota_record = cursor.fetchone()
    conn.close()

    if not quota_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户配额信息不存在"
        )

    quota_limit, quota_used, warning_threshold = quota_record

    return {
        "user_id": user_id,
        "quota_limit": quota_limit,
        "quota_used": quota_used,
        "warning_threshold": warning_threshold,
        "usage_percent": (quota_used / quota_limit * 100) if quota_limit > 0 else 0,
        "unlimited": quota_limit == 0
    }

@app.post("/quota", summary="设置用户配额")
async def set_user_quota(
    quota_data: QuotaSet,
    current_user: TokenData = Depends(get_current_user)
):
    """设置用户配额（仅管理员）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以设置用户配额"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查用户是否存在
    cursor.execute('SELECT id FROM users WHERE id = ?', (quota_data.user_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 检查用户是否已有配额记录
    cursor.execute('SELECT id FROM quotas WHERE user_id = ?', (quota_data.user_id,))
    existing_quota = cursor.fetchone()

    if existing_quota:
        # 更新现有配额
        cursor.execute('UPDATE quotas SET quota_limit = ?, warning_threshold = ? WHERE user_id = ?',
                     (quota_data.quota_limit, quota_data.warning_threshold, quota_data.user_id))
    else:
        # 创建新配额记录
        cursor.execute('INSERT INTO quotas (user_id, quota_limit, quota_used, warning_threshold) VALUES (?, ?, 0, ?)',
                     (quota_data.user_id, quota_data.quota_limit, quota_data.warning_threshold))

    conn.commit()
    conn.close()

    log_action(current_user.user_id, "set_quota", "user", quota_data.user_id,
              f"设置用户配额: {quota_data.quota_limit} 字节")

    return {"message": "用户配额设置成功"}

@app.get("/quota/usage", summary="获取配额使用记录")
async def get_quota_usage(
    user_id: Optional[int] = None,
    limit: int = 50,
    current_user: TokenData = Depends(get_current_user)
):
    """获取配额使用记录"""
    if user_id and user_id != current_user.user_id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以查看其他用户的配额使用记录"
        )

    target_user_id = user_id if user_id else current_user.user_id

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT qu.id, u.username, qu.action, qu.size, f.name as file_name, qu.created_at
        FROM quota_usage qu
        LEFT JOIN users u ON qu.user_id = u.id
        LEFT JOIN files f ON qu.file_id = f.id
        WHERE qu.user_id = ?
        ORDER BY qu.created_at DESC
        LIMIT ?
    ''', (target_user_id, limit))

    usage_records = cursor.fetchall()
    conn.close()

    return [
        {
            "id": record[0],
            "username": record[1],
            "action": record[2],
            "size": record[3],
            "file_name": record[4],
            "created_at": record[5]
        }
        for record in usage_records
    ]

@app.get("/logs", summary="获取操作日志")
async def get_logs(
    limit: int = 50,
    current_user: TokenData = Depends(get_current_user)
):
    """获取操作日志（仅管理员）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以查看日志"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT l.id, u.username, l.action, l.resource_type, l.details, l.ip_address, l.created_at FROM logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC LIMIT ?',
        (limit,)
    )
    logs = cursor.fetchall()
    conn.close()

    return [
        {
            "id": log[0],
            "username": log[1] or "未知用户",
            "action": log[2],
            "resource_type": log[3],
            "details": log[4],
            "ip_address": log[5],
            "created_at": log[6]
        }
        for log in logs
    ]

@app.get("/config", summary="获取配置列表")
async def get_config(current_user: TokenData = Depends(get_current_user)):
    """获取配置列表（仅管理员）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以查看配置"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute('SELECT key, value, description FROM config')
    configs = cursor.fetchall()
    conn.close()

    return [
        {
            "key": config[0],
            "value": config[1],
            "description": config[2]
        }
        for config in configs
    ]

@app.post("/config", summary="添加或更新配置")
async def set_config(
    config_item: ConfigItem,
    current_user: TokenData = Depends(get_current_user)
):
    """添加或更新配置项（仅管理员）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以修改配置"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT OR REPLACE INTO config (key, value, description) VALUES (?, ?, ?)',
        (config_item.key, config_item.value, config_item.description)
    )
    conn.commit()
    conn.close()

    log_action(current_user.user_id, "update_config", "config", 0, f"更新配置项 {config_item.key}")

    return {"message": "配置项已保存"}

@app.delete("/config/{key}", summary="删除配置项")
async def delete_config(
    key: str,
    current_user: TokenData = Depends(get_current_user)
):
    """删除配置项（仅管理员）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以删除配置"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM config WHERE key = ?', (key,))
    conn.commit()
    conn.close()

    log_action(current_user.user_id, "delete_config", "config", 0, f"删除配置项 {key}")

    return {"message": "配置项已删除"}

# 组管理API
@app.post("/groups", summary="创建组")
async def create_group(
    group_data: GroupCreate,
    current_user: TokenData = Depends(get_current_user)
):
    """创建新组（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以创建组"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    try:
        cursor.execute(
            'INSERT INTO groups (name, description) VALUES (?, ?)',
            (group_data.name, group_data.description)
        )
        conn.commit()
        group_id = cursor.lastrowid
        log_action(current_user.user_id, "create_group", "group", group_id, f"创建组 {group_data.name}")
        return {"id": group_id, "name": group_data.name, "description": group_data.description}
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="组名已存在"
        )
    finally:
        conn.close()

@app.get("/groups", summary="获取组列表")
async def list_groups(
    current_user: TokenData = Depends(get_current_user)
):
    """获取所有组列表（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以查看组列表"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, description, created_at FROM groups ORDER BY name')
    groups = cursor.fetchall()
    conn.close()

    return [
        {
            "id": group[0],
            "name": group[1],
            "description": group[2],
            "created_at": group[3]
        }
        for group in groups
    ]

@app.put("/groups/{group_id}", summary="更新组信息")
async def update_group(
    group_id: int,
    group_data: GroupUpdate,
    current_user: TokenData = Depends(get_current_user)
):
    """更新组信息（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以更新组信息"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查组是否存在
    cursor.execute('SELECT id FROM groups WHERE id = ?', (group_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="组不存在"
        )

    # 更新组信息
    update_fields = []
    update_values = []

    if group_data.name is not None:
        update_fields.append("name = ?")
        update_values.append(group_data.name)

    if group_data.description is not None:
        update_fields.append("description = ?")
        update_values.append(group_data.description)

    if not update_fields:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="没有提供要更新的字段"
        )

    update_values.append(group_id)
    update_query = f"UPDATE groups SET {', '.join(update_fields)} WHERE id = ?"

    try:
        cursor.execute(update_query, update_values)
        conn.commit()
        log_action(current_user.user_id, "update_group", "group", group_id, f"更新组信息")
        conn.close()
        return {"message": "组信息更新成功"}
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="组名已存在"
        )

@app.delete("/groups/{group_id}", summary="删除组")
async def delete_group(
    group_id: int,
    current_user: TokenData = Depends(get_current_user)
):
    """删除组（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以删除组"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查组是否存在
    cursor.execute('SELECT id, name FROM groups WHERE id = ?', (group_id,))
    group = cursor.fetchone()
    if not group:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="组不存在"
        )

    # 删除组（会级联删除用户组关联）
    group_name = group[1]
    cursor.execute('DELETE FROM groups WHERE id = ?', (group_id,))
    conn.commit()
    conn.close()

    log_action(current_user.user_id, "delete_group", "group", group_id, f"删除组 {group_name}")

    return {"message": "组删除成功"}

# 用户组关联管理API
class UserGroupAssign(BaseModel):
    user_id: int

@app.post("/groups/{group_id}/users", summary="将用户添加到组")
async def assign_user_to_group(
    group_id: int,
    user_group_data: UserGroupAssign,
    current_user: TokenData = Depends(get_current_user)
):
    """将用户添加到指定组（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以管理用户组关联"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查组是否存在
    cursor.execute('SELECT id, name FROM groups WHERE id = ?', (group_id,))
    group = cursor.fetchone()
    if not group:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="组不存在"
        )

    # 检查用户是否存在
    cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_group_data.user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 检查用户是否已经在此组中
    cursor.execute(
        'SELECT user_id FROM user_groups WHERE user_id = ? AND group_id = ?',
        (user_group_data.user_id, group_id)
    )
    if cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户已在该组中"
        )

    # 添加用户到组
    cursor.execute(
        'INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)',
        (user_group_data.user_id, group_id)
    )
    conn.commit()
    conn.close()

    log_action(current_user.user_id, "assign_user_to_group", "user_group", 0,
              f"将用户 {user[1]} 添加到组 {group[1]}")

    return {"message": f"用户 {user[1]} 已成功添加到组 {group[1]}"}

@app.delete("/groups/{group_id}/users/{user_id}", summary="从组中移除用户")
async def remove_user_from_group(
    group_id: int,
    user_id: int,
    current_user: TokenData = Depends(get_current_user)
):
    """从指定组中移除用户（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以管理用户组关联"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查组是否存在
    cursor.execute('SELECT id, name FROM groups WHERE id = ?', (group_id,))
    group = cursor.fetchone()
    if not group:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="组不存在"
        )

    # 检查用户是否存在
    cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 检查用户是否在此组中
    cursor.execute(
        'SELECT user_id FROM user_groups WHERE user_id = ? AND group_id = ?',
        (user_id, group_id)
    )
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户不在该组中"
        )

    # 从组中移除用户
    cursor.execute(
        'DELETE FROM user_groups WHERE user_id = ? AND group_id = ?',
        (user_id, group_id)
    )
    conn.commit()
    conn.close()

    log_action(current_user.user_id, "remove_user_from_group", "user_group", 0,
              f"从组 {group[1]} 中移除用户 {user[1]}")

    return {"message": f"用户 {user[1]} 已从组 {group[1]} 中移除"}

@app.get("/groups/{group_id}/users", summary="获取组中的用户列表")
async def get_users_in_group(
    group_id: int,
    current_user: TokenData = Depends(get_current_user)
):
    """获取指定组中的所有用户（需要管理员权限）"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员可以查看组用户列表"
        )

    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()

    # 检查组是否存在
    cursor.execute('SELECT id, name FROM groups WHERE id = ?', (group_id,))
    group = cursor.fetchone()
    if not group:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="组不存在"
        )

    # 获取组中的所有用户
    cursor.execute('''
        SELECT u.id, u.username, u.email, u.is_admin, u.created_at
        FROM users u
        INNER JOIN user_groups ug ON u.id = ug.user_id
        WHERE ug.group_id = ?
        ORDER BY u.username
    ''', (group_id,))
    users = cursor.fetchall()
    conn.close()

    return [
        {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "is_admin": bool(user[3]),
            "created_at": user[4]
        }
        for user in users
    ]

@app.get("/", summary="Web界面")
async def web_interface():
    """提供Bootstrap 5响应式Web界面"""
    template_path = Path(__file__).parent / 'templates' / 'web_bootstrap.html'
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>模板文件未找到，请确保 templates/web_bootstrap.html 存在</h1>")

# 原有的内嵌HTML代码已移除，现在使用外部模板文件 templates/web_bootstrap.html

if __name__ == "__main__":
    # 初始化数据库
    init_database()

    # 创建存储目录
    Path("storage").mkdir(exist_ok=True)

    # 解析命令行参数（可以覆盖配置文件）
    parser = argparse.ArgumentParser(description="FilePy 文件服务器 v0.2.0")
    parser.add_argument("--host", help="服务器主机地址（覆盖配置文件）")
    parser.add_argument("--port", type=int, help="服务器端口（覆盖配置文件）")
    args = parser.parse_args()

    # 从配置文件或命令行参数获取服务器配置
    host = args.host or get_config_value('host', section='server', default='0.0.0.0')
    port = args.port or int(get_config_value('port', section='server', default='1966'))

    # 在 uvicorn.run 时，尝试使用环境变量提供的 TLS 证书
    ssl_cert = os.getenv("SSL_CERTFILE")
    ssl_key = os.getenv("SSL_KEYFILE")
    ssl_kwargs = {}
    if ssl_cert and ssl_key:
        ssl_kwargs = {
            "ssl_certfile": ssl_cert,
            "ssl_keyfile": ssl_key
        }

    # 启动服务器
    logger.info(f"FilePy v0.2.0 文件服务器启动中...")
    logger.info(f"配置文件: config.ini")
    protocol = "https" if ssl_cert else "http"
    logger.info(f"监听地址: {protocol}://{host}:{port}")
    logger.info(f"按 CTRL+C 停止服务器")

    try:
        uvicorn.run("FilePy:app", host=host, port=port, reload=False, **ssl_kwargs)
    except KeyboardInterrupt:
        logger.info("服务器已停止")