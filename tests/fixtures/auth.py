# -*- coding: utf-8 -*-
"""
认证相关 fixtures
"""

import sqlite3
from typing import Dict
import pytest
from passlib.context import CryptContext


@pytest.fixture(scope="function")
def create_test_user(init_test_database: sqlite3.Connection):
    """
    创建测试用户

    返回用户信息字典
    """
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    password_hash = pwd_context.hash("test_password")

    cursor = init_test_database.cursor()
    cursor.execute(
        '''INSERT INTO users (username, password_hash, email)
           VALUES (?, ?, ?)''',
        ('testuser', password_hash, 'test@example.com')
    )
    init_test_database.commit()

    user_id = cursor.lastrowid
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()

    return {
        'id': row[0],
        'username': row[1],
        'email': row[3],
        'is_admin': bool(row[4]),
        'password': 'test_password'  # 原始密码，仅用于测试
    }


@pytest.fixture(scope="function")
def create_test_admin(init_test_database: sqlite3.Connection):
    """
    创建测试管理员

    返回管理员信息字典
    """
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    password_hash = pwd_context.hash("admin_password")

    cursor = init_test_database.cursor()
    cursor.execute(
        '''INSERT INTO users (username, password_hash, email, is_admin)
           VALUES (?, ?, ?, ?)''',
        ('testadmin', password_hash, 'admin@example.com', 1)
    )
    init_test_database.commit()

    user_id = cursor.lastrowid
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()

    return {
        'id': row[0],
        'username': row[1],
        'email': row[3],
        'is_admin': bool(row[4]),
        'password': 'admin_password'  # 原始密码，仅用于测试
    }


@pytest.fixture(scope="function")
def get_test_token(create_test_user: Dict) -> str:
    """
    生成测试 JWT Token

    返回模拟的 token 字符串
    """
    # 在实际实现中，这里会使用真实的 JWT 编码
    # 目前返回模拟 token 用于测试
    return f"test_token_{create_test_user['id']}"


@pytest.fixture(scope="function")
def authenticated_headers(get_test_token: str) -> Dict[str, str]:
    """
    生成认证请求头

    返回包含 Authorization 的请求头字典
    """
    return {
        "Authorization": f"Bearer {get_test_token}",
        "Content-Type": "application/json"
    }
