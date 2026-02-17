# -*- coding: utf-8 -*-
"""
收藏服务

处理收藏相关的业务逻辑
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class FavoriteService:
    """收藏服务"""

    def __init__(self, db):
        """
        初始化收藏服务

        Args:
            db: 数据库实例
        """
        self.db = db

    def add_favorite(self, user_id: int, file_path: str, file_name: str,
                     is_dir: bool = False, file_size: int = None) -> bool:
        """
        添加收藏

        Args:
            user_id: 用户ID
            file_path: 文件路径
            file_name: 文件名
            is_dir: 是否是目录
            file_size: 文件大小

        Returns:
            bool: 是否添加成功
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                INSERT OR IGNORE INTO favorites
                (user_id, file_path, file_name, is_dir, file_size)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, file_path, file_name, is_dir, file_size))
        logger.info(f"用户 {user_id} 收藏了 {file_path}")
        return True

    def remove_favorite(self, user_id: int, file_path: str) -> bool:
        """
        取消收藏

        Args:
            user_id: 用户ID
            file_path: 文件路径

        Returns:
            bool: 是否取消成功
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                DELETE FROM favorites
                WHERE user_id = ? AND file_path = ?
            ''', (user_id, file_path))
        logger.info(f"用户 {user_id} 取消收藏 {file_path}")
        return True

    def is_favorite(self, user_id: int, file_path: str) -> bool:
        """
        检查是否已收藏

        Args:
            user_id: 用户ID
            file_path: 文件路径

        Returns:
            bool: 是否已收藏
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                SELECT id FROM favorites
                WHERE user_id = ? AND file_path = ?
            ''', (user_id, file_path))
            return cursor.fetchone() is not None

    def list_favorites(self, user_id: int) -> List[Dict[str, Any]]:
        """
        获取收藏列表

        Args:
            user_id: 用户ID

        Returns:
            List[Dict]: 收藏列表
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                SELECT id, file_path, file_name, is_dir, file_size, created_at
                FROM favorites
                WHERE user_id = ?
                ORDER BY created_at DESC
            ''', (user_id,))
            rows = cursor.fetchall()
            return [
                {
                    'id': r[0],
                    'file_path': r[1],
                    'file_name': r[2],
                    'is_dir': r[3],
                    'file_size': r[4],
                    'created_at': r[5]
                }
                for r in rows
            ]
