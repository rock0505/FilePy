# -*- coding: utf-8 -*-
"""
认证服务

处理用户认证相关的业务逻辑
"""

import logging
from typing import Optional, Dict
from passlib.context import CryptContext

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)
from app.models.user import UserCreate
from app.models.auth import TokenData, TokenResponse


logger = logging.getLogger(__name__)


class AuthService:
    """认证服务"""

    def __init__(self, db):
        """
        初始化认证服务

        Args:
            db: 数据库实例
        """
        self.db = db

    def hash_password(self, password: str) -> str:
        """对密码进行哈希"""
        return hash_password(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """验证密码"""
        return verify_password(plain_password, hashed_password)

    def create_user(self, user_data: UserCreate, is_admin: bool = False) -> int:
        """
        创建新用户

        Args:
            user_data: 用户创建数据
            is_admin: 是否为管理员

        Returns:
            int: 新用户的 ID
        """
        password_hash = self.hash_password(user_data.password)

        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''INSERT INTO users (username, password_hash, email, is_admin)
                   VALUES (?, ?, ?, ?)''',
                (user_data.username, password_hash, user_data.email, is_admin)
            )
            user_id = cursor.lastrowid

        logger.info(f"创建用户: {user_data.username} (ID: {user_id})")
        return user_id

    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """
        验证用户凭据

        Args:
            username: 用户名
            password: 密码

        Returns:
            Optional[Dict]: 用户信息，验证失败返回 None
        """
        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''SELECT id, username, password_hash, email, is_admin, force_password_change
                   FROM users WHERE username = ?''',
                (username,)
            )
            user = cursor.fetchone()

        if not user:
            return None

        # 转换为字典
        user_dict = {
            'id': user[0],
            'username': user[1],
            'password_hash': user[2],
            'email': user[3],
            'is_admin': bool(user[4]),
            'force_password_change': bool(user[5])
        }

        # 验证密码
        if not self.verify_password(password, user_dict['password_hash']):
            return None

        return user_dict

    def login(self, username: str, password: str) -> Optional[TokenResponse]:
        """
        用户登录

        Args:
            username: 用户名
            password: 密码

        Returns:
            Optional[TokenResponse]: Token 响应，登录失败返回 None
        """
        user = self.authenticate_user(username, password)

        if not user:
            return None

        # 创建 Token
        token_data = {
            'user_id': user['id'],
            'username': user['username'],
            'is_admin': user['is_admin']
        }

        access_token = create_access_token(token_data)

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            force_password_change=user['force_password_change']
        )

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """
        根据 ID 获取用户

        Args:
            user_id: 用户 ID

        Returns:
            Optional[Dict]: 用户信息，不存在返回 None
        """
        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''SELECT id, username, email, is_admin, force_password_change, created_at
                   FROM users WHERE id = ?''',
                (user_id,)
            )
            user = cursor.fetchone()

        if not user:
            return None

        return {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'is_admin': bool(user[3]),
            'force_password_change': bool(user[4]),
            'created_at': user[5]
        }

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """
        根据用户名获取用户

        Args:
            username: 用户名

        Returns:
            Optional[Dict]: 用户信息，不存在返回 None
        """
        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''SELECT id, username, email, is_admin, force_password_change, created_at
                   FROM users WHERE username = ?''',
                (username,)
            )
            user = cursor.fetchone()

        if not user:
            return None

        return {
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'is_admin': bool(user[3]),
            'force_password_change': bool(user[4]),
            'created_at': user[5]
        }

    def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str
    ) -> bool:
        """
        修改密码

        Args:
            user_id: 用户 ID
            old_password: 原密码
            new_password: 新密码

        Returns:
            bool: 是否修改成功
        """
        # 获取用户当前密码
        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''SELECT password_hash FROM users WHERE id = ?''',
                (user_id,)
            )
            result = cursor.fetchone()

        if not result:
            return False

        current_hash = result[0]

        # 验证原密码
        if not self.verify_password(old_password, current_hash):
            return False

        # 更新密码
        new_hash = self.hash_password(new_password)

        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''UPDATE users SET password_hash = ?, force_password_change = 0
                   WHERE id = ?''',
                (new_hash, user_id)
            )

        logger.info(f"用户 {user_id} 修改密码成功")
        return True
