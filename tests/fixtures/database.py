# -*- coding: utf-8 -*-
"""
数据库相关 fixtures
"""

import sqlite3
from typing import Generator
import pytest
from app.core.database import Database, init_database


@pytest.fixture(scope="function")
def init_test_database():
    """
    初始化测试数据库

    返回内存数据库连接，测试结束后自动关闭
    """
    conn = sqlite3.connect(":memory:")

    # 创建所有表
    _create_tables(conn)

    # 插入默认数据
    _insert_default_data(conn)

    yield conn

    conn.close()


@pytest.fixture(scope="function")
def db_cursor(init_test_database: sqlite3.Connection):
    """提供数据库游标"""
    cursor = init_test_database.cursor()
    yield cursor
    cursor.close()


@pytest.fixture(scope="function")
def test_database():
    """
    提供完整的 Database 对象

    返回初始化好的 Database 对象，用于服务测试
    """
    db = Database(":memory:")

    # 初始化数据库表
    init_database(db)

    yield db

    db.close()


def _create_tables(conn: sqlite3.Connection):
    """创建所有数据库表"""
    cursor = conn.cursor()

    # 用户表
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

    # 组表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 用户组关联表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_groups (
            user_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (user_id, group_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    ''')

    # 权限表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    ''')

    # 文件表
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

    # 日志表
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

    # 配额表
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

    # 配置表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            description TEXT
        )
    ''')

    conn.commit()


def _insert_default_data(conn: sqlite3.Connection):
    """插入默认数据"""
    cursor = conn.cursor()

    # 默认权限
    permissions = [
        ('read', '读取权限'),
        ('write', '写入权限'),
        ('execute', '执行权限'),
        ('delete', '删除权限')
    ]
    for name, desc in permissions:
        cursor.execute(
            'INSERT OR IGNORE INTO permissions (name, description) VALUES (?, ?)',
            (name, desc)
        )

    # 默认配置
    configs = [
        ('max_upload_size', '104857600', '最大上传文件大小(字节)'),
        ('allow_registration', 'false', '是否允许用户注册'),
    ]
    for key, value, desc in configs:
        cursor.execute(
            'INSERT OR IGNORE INTO config (key, value, description) VALUES (?, ?, ?)',
            (key, value, desc)
        )

    conn.commit()
