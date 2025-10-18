#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FilePy v0.1.2 - 轻量级文件服务器
使用Python + FastAPI + SQLite实现
"""

import os
import sys
import sqlite3
import hashlib
import json
import argparse
import logging
from datetime import datetime
from typing import Optional, List, Dict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel
import uvicorn

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

    # 创建默认管理员用户 (密码为admin123)
    password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    cursor.execute(
        'INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
        ('admin', password_hash, True)
    )

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
    version="1.0.0"
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    """对密码进行哈希处理"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    return hash_password(plain_password) == hashed_password

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

def get_config_value(key: str, default_value: str = "") -> str:
    """获取配置值"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM config WHERE key = ?', (key,))
    record = cursor.fetchone()
    conn.close()

    if record:
        return record[0]
    return default_value

# API路由

@app.post("/auth/login", summary="用户登录")
async def login(user_data: UserLogin):
    """用户登录接口"""
    conn = sqlite3.connect('filepy.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, username, password_hash, is_admin FROM users WHERE username = ?',
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
    return {"access_token": token, "token_type": "bearer"}

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

@app.post("/files/upload", summary="上传文件")
async def upload_file(
    file: UploadFile = File(...),
    path: str = Form("/"),
    current_user: TokenData = Depends(get_current_user)
):
    """上传文件"""
    try:
        # 检查文件大小限制
        content = await file.read()
        file_size = len(content)

        # 获取最大上传大小配置
        max_upload_size_str = get_config_value('max_upload_size', '104857600')  # 默认100MB
        try:
            max_upload_size = int(max_upload_size_str)
        except ValueError:
            max_upload_size = 104857600  # 默认100MB

        if file_size > max_upload_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"文件大小超过限制 ({max_upload_size} bytes)"
            )

        # 重置文件指针
        await file.seek(0)

        # 确保存储目录存在
        storage_path = Path("storage")
        storage_path.mkdir(exist_ok=True)

        # 构建完整路径
        target_dir = storage_path / path.lstrip("/")
        target_dir.mkdir(parents=True, exist_ok=True)

        file_path = target_dir / file.filename

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

        return {
            "id": file_id,
            "filename": file.filename,
            "size": stat.st_size,
            "content_type": file.content_type
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
    """提供简单的Web界面"""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>FilePy 文件服务器</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; padding: 20px; }
            .header { background: #007cba; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
            .login-container { background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-top: 20px; text-align: center; }
            .main-container { background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-top: 20px; display: none; }
            .file-list { margin-top: 20px; }
            .file-item { padding: 10px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
            .file-item:hover { background: #f9f9f9; }
            .upload-form { margin-top: 20px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9; }
            button { background: #007cba; color: white; border: none; padding: 10px 20px; border-radius: 3px; cursor: pointer; margin: 5px; }
            button:hover { background: #005a87; }
            input, select { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 3px; }
            .logout-btn { background: #dc3545; float: right; }
            .logout-btn:hover { background: #c82333; }
            .hidden { display: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>FilePy 文件服务器</h1>
                <p>轻量级安全文件管理解决方案</p>
            </div>

            <!-- 登录界面 -->
            <div id="loginContainer" class="login-container">
                <h2>用户登录</h2>
                <div>
                    <input type="text" id="username" placeholder="用户名" required><br>
                    <input type="password" id="password" placeholder="密码" required><br>
                    <button onclick="login()">登录</button>
                </div>
                <p id="loginMessage" style="color: red;"></p>
            </div>

            <!-- 主界面（登录后显示） -->
            <div id="mainContainer" class="main-container">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h2>文件管理</h2>
                    <button class="logout-btn" onclick="logout()">退出登录</button>
                </div>

                <div class="upload-form">
                    <h3>上传文件</h3>
                    <form id="uploadForm">
                        <input type="file" id="fileInput" required>
                        <button type="submit">上传</button>
                    </form>
                </div>

                <div class="file-list">
                    <h3>文件列表</h3>
                    <div id="fileList">加载中...</div>
                </div>
            </div>
        </div>

        <script>
            // 存储认证令牌
            let authToken = null;
            let currentUser = null;

            // 页面加载时检查是否有存储的认证信息
            window.onload = function() {
                const storedToken = localStorage.getItem('filepy_token');
                const storedUser = localStorage.getItem('filepy_user');
                if (storedToken && storedUser) {
                    authToken = storedToken;
                    currentUser = JSON.parse(storedUser);
                    showMainInterface();
                    loadFiles();
                }
            };

            // 登录函数
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const messageElement = document.getElementById('loginMessage');

                if (!username || !password) {
                    messageElement.textContent = "用户名和密码不能为空";
                    return;
                }

                try {
                    const response = await fetch('/auth/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({username, password})
                    });

                    if (response.ok) {
                        const data = await response.json();
                        authToken = data.access_token;
                        currentUser = null;

                        // 存储认证信息到localStorage
                        localStorage.setItem('filepy_token', authToken);
                        localStorage.removeItem('filepy_user');

                        messageElement.textContent = "";
                        showMainInterface();
                        loadFiles();
                    } else {
                        const error = await response.json();
                        messageElement.textContent = "登录失败: " + error.detail;
                    }
                } catch (error) {
                    messageElement.textContent = "登录请求失败: " + error.message;
                }
            }

            // 退出登录函数
            function logout() {
                authToken = null;
                currentUser = null;

                // 清除存储的认证信息
                localStorage.removeItem('filepy_token');
                localStorage.removeItem('filepy_user');

                // 显示登录界面，隐藏主界面
                document.getElementById('loginContainer').style.display = 'block';
                document.getElementById('mainContainer').style.display = 'none';
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';
            }

            // 显示主界面
            function showMainInterface() {
                document.getElementById('loginContainer').style.display = 'none';
                document.getElementById('mainContainer').style.display = 'block';
            }

            // 加载文件列表
            async function loadFiles() {
                if (!authToken) {
                    document.getElementById('fileList').innerHTML = '<p>请先登录</p>';
                    return;
                }

                try {
                    const response = await fetch('/files', {
                        headers: {
                            'Authorization': `Bearer ${authToken}`
                        }
                    });

                    if (response.ok) {
                        const files = await response.json();
                        displayFiles(files);
                    } else {
                        document.getElementById('fileList').innerHTML = '<p>加载文件列表失败</p>';
                    }
                } catch (error) {
                    document.getElementById('fileList').innerHTML = '<p>加载文件列表失败: ' + error.message + '</p>';
                }
            }

            // 显示文件列表
            function displayFiles(files) {
                const listElement = document.getElementById('fileList');

                if (files.length === 0) {
                    listElement.innerHTML = '<p>没有文件</p>';
                    return;
                }

                listElement.innerHTML = files.map(file => `
                    <div class="file-item">
                        <div>
                            <strong>${file.name}</strong>
                            ${file.is_dir ? '(目录)' : `(${(file.size || 0)} bytes)`}
                            <br><small>修改时间: ${file.modified || '未知'}</small>
                        </div>
                        <div>
                            ${!file.is_dir ? `<button onclick="downloadFile('${file.path}')">下载</button>` : ''}
                            <button onclick="deleteFile('${file.path}')">删除</button>
                        </div>
                    </div>
                `).join('');
            }

            // 下载文件
            async function downloadFile(filePath) {
                if (!authToken) {
                    alert("请先登录");
                    return;
                }

                try {
                    const response = await fetch(`/files/download/${filePath}`, {
                        headers: {
                            'Authorization': `Bearer ${authToken}`
                        }
                    });

                    if (response.ok) {
                        const blob = await response.blob();
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filePath.split('/').pop();
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                    } else {
                        alert("文件下载失败");
                    }
                } catch (error) {
                    alert("文件下载失败: " + error.message);
                }
            }

            // 删除文件
            async function deleteFile(filePath) {
                if (!authToken) {
                    alert("请先登录");
                    return;
                }

                if (!confirm("确定要删除这个文件吗？")) {
                    return;
                }

                try {
                    const response = await fetch(`/files/${filePath}`, {
                        method: 'DELETE',
                        headers: {
                            'Authorization': `Bearer ${authToken}`
                        }
                    });

                    if (response.ok) {
                        alert("文件删除成功");
                        loadFiles(); // 重新加载文件列表
                    } else {
                        const error = await response.json();
                        alert("文件删除失败: " + error.detail);
                    }
                } catch (error) {
                    alert("文件删除失败: " + error.message);
                }
            }

            // 上传文件处理
            document.getElementById('uploadForm').addEventListener('submit', async (e) => {
                e.preventDefault();

                if (!authToken) {
                    alert("请先登录");
                    return;
                }

                const fileInput = document.getElementById('fileInput');
                if (!fileInput.files[0]) {
                    alert("请选择要上传的文件");
                    return;
                }

                const formData = new FormData();
                formData.append('file', fileInput.files[0]);

                try {
                    const response = await fetch('/files/upload', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${authToken}`
                        },
                        body: formData
                    });

                    if (response.ok) {
                        const result = await response.json();
                        alert("文件上传成功: " + result.filename);
                        loadFiles(); // 重新加载文件列表
                        fileInput.value = ''; // 清空文件选择
                    } else {
                        const error = await response.json();
                        alert("文件上传失败: " + error.detail);
                    }
                } catch (error) {
                    alert("文件上传失败: " + error.message);
                }
            });

            // 支持回车键登录
            document.getElementById('password').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    login();
                }
            });
        </script>
    </body>
    </html>
    """)

if __name__ == "__main__":
    # 初始化数据库
    init_database()

    # 创建存储目录
    Path("storage").mkdir(exist_ok=True)

    # 解析命令行参数
    parser = argparse.ArgumentParser(description="FilePy 文件服务器")
    parser.add_argument("--host", default="0.0.0.0", help="服务器主机地址")
    parser.add_argument("--port", type=int, default=1966, help="服务器端口")
    args = parser.parse_args()

    # 启动服务器
    logger.info(f"FilePy 文件服务器启动中... http://{args.host}:{args.port}")
    uvicorn.run("FilePy:app", host=args.host, port=args.port, reload=False)
