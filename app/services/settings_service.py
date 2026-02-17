# -*- coding: utf-8 -*-
"""
设置服务

处理用户设置和系统信息相关的业务逻辑
"""

import logging
import os
import platform
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)


class SettingsService:
    """设置服务"""

    def __init__(self, db, storage_path: str = "storage"):
        """
        初始化设置服务

        Args:
            db: 数据库实例
            storage_path: 存储目录路径
        """
        self.db = db
        self.storage_path = Path(storage_path)

    def get_user_settings(self, user_id: int) -> Dict[str, Any]:
        """
        获取用户设置

        Args:
            user_id: 用户ID

        Returns:
            Dict: 用户设置
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                SELECT theme, view_mode, items_per_page, auto_refresh, confirm_delete
                FROM user_settings WHERE user_id = ?
            ''', (user_id,))
            row = cursor.fetchone()
            if row:
                return {
                    'theme': row[0],
                    'view_mode': row[1],
                    'items_per_page': row[2],
                    'auto_refresh': bool(row[3]),
                    'confirm_delete': bool(row[4])
                }
            # 返回默认设置
            return {
                'theme': 'light',
                'view_mode': 'list',
                'items_per_page': 50,
                'auto_refresh': True,
                'confirm_delete': True
            }

    def update_user_settings(self, user_id: int, settings: Dict[str, Any]) -> bool:
        """
        更新用户设置

        Args:
            user_id: 用户ID
            settings: 设置字典

        Returns:
            bool: 是否更新成功
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO user_settings (user_id, theme, view_mode, items_per_page, auto_refresh, confirm_delete)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    theme = excluded.theme,
                    view_mode = excluded.view_mode,
                    items_per_page = excluded.items_per_page,
                    auto_refresh = excluded.auto_refresh,
                    confirm_delete = excluded.confirm_delete,
                    updated_at = CURRENT_TIMESTAMP
            ''', (
                user_id,
                settings.get('theme', 'light'),
                settings.get('view_mode', 'list'),
                settings.get('items_per_page', 50),
                settings.get('auto_refresh', True),
                settings.get('confirm_delete', True)
            ))
        logger.info(f"用户 {user_id} 更新了设置")
        return True

    def get_storage_info(self) -> Dict[str, Any]:
        """
        获取存储信息

        Returns:
            Dict: 存储信息
        """
        total_space = 0
        used_space = 0
        file_count = 0
        folder_count = 0

        if self.storage_path.exists():
            # 计算使用空间
            for item in self.storage_path.rglob('*'):
                if item.is_file():
                    used_space += item.stat().st_size
                    file_count += 1
                elif item.is_dir():
                    folder_count += 1

            # 获取磁盘总空间
            if platform.system() == 'Windows':
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(str(self.storage_path)),
                    None,
                    ctypes.pointer(total_bytes),
                    ctypes.pointer(free_bytes)
                )
                total_space = total_bytes.value
            else:
                # Unix-like 系统
                stat = os.statvfs(str(self.storage_path))
                total_space = stat.f_frsize * stat.f_blocks

        return {
            'used_space': used_space,
            'total_space': total_space,
            'file_count': file_count,
            'folder_count': folder_count
        }
