# -*- coding: utf-8 -*-
"""
数据库模块

包含数据库连接、初始化和基本操作
"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from .config import settings


logger = logging.getLogger(__name__)


class Database:
    """数据库连接管理"""

    def __init__(self, db_path: str):
        """
        初始化数据库连接

        Args:
            db_path: 数据库文件路径
        """
        self.db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        """
        获取数据库连接

        Returns:
            sqlite3.Connection: 数据库连接
        """
        if self._connection is None:
            self._connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False
            )
            # 启用外键约束
            self._connection.execute("PRAGMA foreign_keys = ON")
            # 使用 Row Factory，可以通过列名访问
            self._connection.row_factory = sqlite3.Row

        return self._connection

    def close(self):
        """关闭数据库连接"""
        if self._connection:
            self._connection.close()
            self._connection = None

    @contextmanager
    def get_cursor(self):
        """
        获取数据库游标上下文管理器

        用法:
            with db.get_cursor() as cursor:
                cursor.execute("SELECT * FROM users")
        """
        conn = self.connect()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"数据库操作失败: {e}")
            raise


def get_database() -> Database:
    """
    获取数据库实例

    Returns:
        Database: 数据库实例
    """
    # 如果是测试模式，使用内存数据库
    if settings.TESTING:
        return Database(":memory:")

    # 解析数据库 URL
    db_url = settings.DATABASE_URL

    if db_url.startswith("sqlite:///"):
        db_path = db_url.replace("sqlite:///", "")
        return Database(db_path)

    raise ValueError(f"不支持的数据库类型: {db_url}")


def init_database(db: Database):
    """
    初始化数据库表结构

    Args:
        db: 数据库实例
    """
    with db.get_cursor() as cursor:
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

        # 创建配置表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                description TEXT
            )
        ''')

        logger.info("数据库表结构初始化完成")

    # 插入默认数据
    _insert_default_data(db)


def _insert_default_data(db: Database):
    """插入默认数据"""
    from app.core.security import hash_password

    with db.get_cursor() as cursor:
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

        # 创建默认管理员用户 (用户名: admin, 密码: admin123)
        # 首次登录后建议修改密码
        password_hash = hash_password('admin123')
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password_hash, is_admin, force_password_change) VALUES (?, ?, ?, ?)',
            ('admin', password_hash, True, False)
        )

        # 默认配置
        default_configs = [
            ('max_upload_size', str(settings.MAX_UPLOAD_SIZE), '最大上传文件大小(字节)'),
            ('allow_registration', 'false', '是否允许用户注册'),
        ]
        for config_key, config_value, config_desc in default_configs:
            cursor.execute(
                'INSERT OR IGNORE INTO config (key, value, description) VALUES (?, ?, ?)',
                (config_key, config_value, config_desc)
            )

        logger.info("默认数据插入完成")
        logger.info("默认管理员账户: admin / admin123")
