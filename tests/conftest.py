# -*- coding: utf-8 -*-
"""
pytest 配置文件

定义全局 fixtures 和测试配置
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import AsyncGenerator, Generator
import pytest
import sqlite3

# 将项目根目录添加到 Python 路径
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# 测试配置
# =============================================================================

@pytest.fixture(scope="session")
def test_config():
    """测试配置"""
    return {
        "test_upload_dir": tempfile.mkdtemp(prefix="filepy_upload_"),
        "test_db_path": ":memory:",
        "test_storage_dir": tempfile.mkdtemp(prefix="filepy_storage_"),
    }


# =============================================================================
# 临时目录 fixtures
# =============================================================================

@pytest.fixture(scope="function")
def temp_dir() -> Generator[Path, None, None]:
    """
    创建临时目录，测试后自动清理

    用法:
        def test_something(temp_dir: Path):
            file_path = temp_dir / "test.txt"
            file_path.write_text("content")
    """
    temp_path = Path(tempfile.mkdtemp(prefix="filepy_test_"))
    yield temp_path
    # 清理临时目录
    if temp_path.exists():
        shutil.rmtree(temp_path)


@pytest.fixture(scope="function")
def temp_file(temp_dir: Path) -> Path:
    """
    创建临时文件

    用法:
        def test_something(temp_file: Path):
            content = temp_file.read_text()
    """
    file_path = temp_dir / "test_file.txt"
    file_path.write_text("测试内容 Test Content")
    return file_path


# =============================================================================
# 数据库 fixtures
# =============================================================================

@pytest.fixture(scope="function")
def test_db():
    """
    创建测试数据库（内存模式）

    自动初始化表结构，测试后自动销毁
    """
    # 创建内存数据库
    conn = sqlite3.connect(":memory:")
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
            permissions TEXT,
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

    # 创建配额表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quotas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            quota_limit INTEGER,
            quota_used INTEGER DEFAULT 0,
            warning_threshold INTEGER DEFAULT 80,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # 插入测试数据
    # 默认权限
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

    # 测试用户
    test_users = [
        ('test_admin', 'admin_hash', True, True),
        ('test_user', 'user_hash', False, False),
    ]
    for username, pwd_hash, is_admin, force_pwd in test_users:
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password_hash, is_admin, force_password_change) VALUES (?, ?, ?, ?)',
            (username, pwd_hash, is_admin, force_pwd)
        )

    conn.commit()

    yield conn

    # 清理
    conn.close()


# =============================================================================
# 认证 fixtures
# =============================================================================

@pytest.fixture(scope="function")
def test_user(test_db):
    """创建测试用户"""
    cursor = test_db.cursor()
    cursor.execute(
        'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
        ('testuser', 'hashed_password', 'test@example.com')
    )
    test_db.commit()
    user_id = cursor.lastrowid
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    return {
        'id': user[0],
        'username': user[1],
        'email': user[3],
        'is_admin': bool(user[4])
    }


@pytest.fixture(scope="function")
def test_admin(test_db):
    """创建测试管理员"""
    cursor = test_db.cursor()
    cursor.execute(
        'INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)',
        ('testadmin', 'hashed_password', 'admin@example.com', 1)
    )
    test_db.commit()
    user_id = cursor.lastrowid
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    return {
        'id': user[0],
        'username': user[1],
        'email': user[3],
        'is_admin': bool(user[4])
    }


@pytest.fixture(scope="function")
def auth_headers():
    """生成认证头（模拟 JWT token）"""
    return {"Authorization": "Bearer test_token_12345"}


# =============================================================================
# 文件存储 fixtures
# =============================================================================

@pytest.fixture(scope="function")
def test_storage_dir(temp_dir: Path) -> Path:
    """
    创建测试存储目录

    用法:
        def test_file_operations(test_storage_dir: Path):
            file_path = test_storage_dir / "test.txt"
            file_path.write_text("content")
    """
    storage_path = temp_dir / "storage"
    storage_path.mkdir(exist_ok=True)
    return storage_path


@pytest.fixture(scope="function")
def sample_files(test_storage_dir: Path) -> dict:
    """
    创建示例文件

    返回:
        dict: 包含各种类型示例文件的字典
    """
    files = {}

    # 创建文本文件
    txt_file = test_storage_dir / "test.txt"
    txt_file.write_text("这是测试文本文件\nTest Text File")
    files['txt'] = txt_file

    # 创建目录
    test_dir = test_storage_dir / "test_folder"
    test_dir.mkdir()
    files['dir'] = test_dir

    # 创建 JSON 文件
    json_file = test_storage_dir / "test.json"
    json_file.write_text('{"key": "value", "number": 123}')
    files['json'] = json_file

    return files


# =============================================================================
# FastAPI 测试客户端 fixtures (用于集成测试)
# =============================================================================

@pytest.fixture(scope="function")
async def async_client():
    """
    异步 HTTP 测试客户端

    用于集成测试和 E2E 测试
    """
    import httpx
    from app.main import app

    async with httpx.AsyncClient(
        app=app,
        base_url="http://test"
    ) as client:
        yield client


# =============================================================================
# 环境变量 fixtures
# =============================================================================

@pytest.fixture(scope="function", autouse=True)
def set_test_env():
    """
    自动设置测试环境变量

    autouse=True 表示所有测试自动使用此 fixture
    """
    original_env = os.environ.copy()

    # 设置测试环境变量
    os.environ["FILEPY_TESTING"] = "true"
    os.environ["FILEPY_SECRET_KEY"] = "test-secret-key-for-testing-only"
    os.environ["FILEPY_DATABASE_URL"] = "sqlite:///:memory:"

    yield

    # 恢复原始环境变量
    for key, value in original_env.items():
        os.environ[key] = value

    # 删除测试期间新增的环境变量
    for key in set(os.environ.keys()) - set(original_env.keys()):
        del os.environ[key]


# =============================================================================
# Database 对象 fixture (用于服务测试)
# =============================================================================

@pytest.fixture(scope="function")
def test_database():
    """
    提供完整的 Database 对象

    返回初始化好的 Database 对象，用于服务测试
    """
    from app.core.database import Database, init_database

    db = Database(":memory:")

    # 初始化数据库表
    init_database(db)

    yield db

    db.close()
