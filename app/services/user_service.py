# -*- coding: utf-8 -*-
"""
用户服务

处理用户管理相关的业务逻辑
"""

import logging
from typing import List, Optional, Dict

from app.models.user import UserCreate, UserUpdate


logger = logging.getLogger(__name__)


class UserService:
    """用户服务"""

    def __init__(self, db):
        """
        初始化用户服务

        Args:
            db: 数据库实例
        """
        self.db = db

    def create_user(self, user_data: UserCreate, is_admin: bool = False) -> int:
        """
        创建新用户

        Args:
            user_data: 用户创建数据
            is_admin: 是否为管理员

        Returns:
            int: 新用户的 ID
        """
        from app.services.auth_service import AuthService

        auth_service = AuthService(self.db)
        return auth_service.create_user(user_data, is_admin)

    def get_user(self, user_id: int) -> Optional[Dict]:
        """
        获取用户信息

        Args:
            user_id: 用户 ID

        Returns:
            Optional[Dict]: 用户信息，不存在返回 None
        """
        from app.services.auth_service import AuthService

        auth_service = AuthService(self.db)
        return auth_service.get_user_by_id(user_id)

    def list_users(self) -> List[Dict]:
        """
        列出所有用户

        Returns:
            List[Dict]: 用户列表
        """
        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''SELECT id, username, email, is_admin, created_at
                   FROM users ORDER BY username'''
            )
            users = cursor.fetchall()

        return [
            {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'is_admin': bool(user[3]),
                'created_at': user[4]
            }
            for user in users
        ]

    def update_user(self, user_id: int, update_data: UserUpdate) -> bool:
        """
        更新用户信息

        Args:
            user_id: 用户 ID
            update_data: 更新数据

        Returns:
            bool: 是否更新成功
        """
        updates = []

        if update_data.email is not None:
            updates.append(("email", update_data.email))

        if not updates:
            return False

        set_clause = ", ".join(f"{k} = ?" for k, _ in updates)
        values = [v for _, v in updates] + [user_id]

        with self.db.get_cursor() as cursor:
            cursor.execute(
                f'''UPDATE users SET {set_clause} WHERE id = ?''',
                values
            )

        logger.info(f"更新用户 {user_id}")
        return True

    def delete_user(self, user_id: int) -> bool:
        """
        删除用户

        Args:
            user_id: 用户 ID

        Returns:
            bool: 是否删除成功
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

        logger.info(f"删除用户 {user_id}")
        return True
