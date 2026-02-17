# -*- coding: utf-8 -*-
"""
文件服务

处理文件操作相关的业务逻辑
"""

import os
import shutil
import logging
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

from app.models.file import (
    FileInfo,
    FileRename,
    FolderCreate,
    BatchDelete,
    SearchQuery
)


logger = logging.getLogger(__name__)


class FileService:
    """文件服务"""

    def __init__(self, db, storage_path: str = "storage"):
        """
        初始化文件服务

        Args:
            db: 数据库实例
            storage_path: 存储目录路径
        """
        self.db = db
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)

    def list_files(self, path: str = "/") -> List[FileInfo]:
        """
        列出目录下的文件

        Args:
            path: 目录路径

        Returns:
            List[FileInfo]: 文件列表
        """
        full_path = self.storage_path / path.lstrip("/")

        if not full_path.exists() or not full_path.is_dir():
            logger.warning(f"目录不存在: {full_path}")
            return []

        items = []

        for item in full_path.iterdir():
            stat = item.stat()
            items.append(FileInfo(
                name=item.name,
                path=str(item.relative_to(self.storage_path)),
                size=stat.st_size if item.is_file() else None,
                mime_type=self._get_mime_type(item),
                is_dir=item.is_dir(),
                modified=datetime.fromtimestamp(stat.st_mtime).isoformat()
            ))

        # 按名称排序，目录优先
        items.sort(key=lambda x: (not x.is_dir, x.name.lower()))

        return items

    def create_folder(self, folder_data: FolderCreate) -> FileInfo:
        """
        创建目录

        Args:
            folder_data: 目录创建数据

        Returns:
            FileInfo: 创建的目录信息
        """
        target_dir = self.storage_path / folder_data.path.lstrip("/")
        target_dir.mkdir(parents=True, exist_ok=True)

        new_folder = target_dir / folder_data.name

        if new_folder.exists():
            raise ValueError(f"目录已存在: {folder_data.name}")

        new_folder.mkdir()

        logger.info(f"创建目录: {new_folder}")

        return FileInfo(
            name=folder_data.name,
            path=str(new_folder.relative_to(self.storage_path)),
            is_dir=True,
            modified=datetime.now().isoformat()
        )

    def rename_file(self, rename_data: FileRename) -> bool:
        """
        重命名文件或目录

        Args:
            rename_data: 重命名数据

        Returns:
            bool: 是否重命名成功
        """
        old_path = self.storage_path / rename_data.old_path.lstrip("/")

        if not old_path.exists():
            logger.warning(f"文件不存在: {old_path}")
            return False

        parent_dir = old_path.parent
        new_path = parent_dir / rename_data.new_name

        if new_path.exists():
            logger.warning(f"目标名称已存在: {rename_data.new_name}")
            return False

        old_path.rename(new_path)

        # 更新数据库记录
        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''UPDATE files SET path = ?, name = ? WHERE path = ?''',
                (str(new_path), rename_data.new_name, str(old_path))
            )

        logger.info(f"重命名: {old_path} -> {new_path}")
        return True

    def delete_file(self, file_path: str) -> bool:
        """
        删除文件或目录

        Args:
            file_path: 文件路径

        Returns:
            bool: 是否删除成功
        """
        full_path = self.storage_path / file_path.lstrip("/")

        if not full_path.exists():
            logger.warning(f"文件不存在: {full_path}")
            return False

        # 从数据库删除记录
        with self.db.get_cursor() as cursor:
            cursor.execute(
                '''DELETE FROM files WHERE path = ?''',
                (str(full_path),)
            )

        # 删除物理文件
        if full_path.is_file():
            full_path.unlink()
        else:
            shutil.rmtree(full_path)

        logger.info(f"删除文件: {full_path}")
        return True

    def batch_delete(self, paths: List[str]) -> Dict:
        """
        批量删除文件

        Args:
            paths: 文件路径列表

        Returns:
            Dict: 删除结果统计
        """
        success_count = 0
        failed_items = []

        for file_path in paths:
            try:
                if self.delete_file(file_path):
                    success_count += 1
                else:
                    failed_items.append({"path": file_path, "error": "文件不存在"})
            except Exception as e:
                failed_items.append({"path": file_path, "error": str(e)})

        return {
            "success_count": success_count,
            "failed_count": len(failed_items),
            "failed_items": failed_items
        }

    def search_files(self, query: SearchQuery) -> List[FileInfo]:
        """
        搜索文件

        Args:
            query: 搜索查询

        Returns:
            List[FileInfo]: 搜索结果
        """
        search_path = self.storage_path / query.path.lstrip("/")

        if not search_path.exists():
            return []

        results = []

        # 递归搜索
        for item in search_path.rglob("*"):
            # 跳过隐藏文件
            if item.name.startswith("."):
                continue

            # 名称过滤
            if query.name:
                if query.name.lower() not in item.name.lower():
                    continue

            # 大小过滤
            if query.min_size is not None or query.max_size is not None:
                if item.is_file():
                    size = item.stat().st_size
                    if query.min_size is not None and size < query.min_size:
                        continue
                    if query.max_size is not None and size > query.max_size:
                        continue

            # 日期过滤
            if query.start_date or query.end_date:
                mtime = datetime.fromtimestamp(item.stat().st_mtime)
                if query.start_date:
                    start_dt = datetime.fromisoformat(query.start_date)
                    if mtime < start_dt:
                        continue
                if query.end_date:
                    end_dt = datetime.fromisoformat(query.end_date)
                    if mtime > end_dt:
                        continue

            results.append(FileInfo(
                name=item.name,
                path=str(item.relative_to(self.storage_path)),
                size=item.stat().st_size if item.is_file() else None,
                is_dir=item.is_dir(),
                modified=datetime.fromtimestamp(item.stat().st_mtime).isoformat()
            ))

        return results

    def get_file_path(self, file_path: str) -> Path:
        """
        获取文件的完整路径

        Args:
            file_path: 相对路径

        Returns:
            Path: 完整路径
        """
        return self.storage_path / file_path.lstrip("/")

    def _get_mime_type(self, path: Path) -> Optional[str]:
        """
        获取文件 MIME 类型

        Args:
            path: 文件路径

        Returns:
            Optional[str]: MIME 类型
        """
        if path.is_dir():
            return None

        # 根据扩展名判断
        ext_map = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.mp3': 'audio/mpeg',
            '.mp4': 'video/mp4',
            '.zip': 'application/zip',
            '.json': 'application/json',
        }

        return ext_map.get(path.suffix.lower())

    def log_action(self, user_id: int, action: str, resource_type: str,
                   resource_path: str, details: str = None) -> None:
        """
        记录操作日志

        Args:
            user_id: 用户ID
            action: 操作类型 (file_view, file_upload, file_download, file_delete, file_rename, folder_create)
            resource_type: 资源类型 (file, folder)
            resource_path: 资源路径
            details: 详细信息
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                INSERT INTO logs (user_id, action, resource_type, details)
                VALUES (?, ?, ?, ?)
            ''', (user_id, action, resource_type, details or resource_path))

    def get_recent_files(self, user_id: int, limit: int = 20) -> List[Dict]:
        """
        获取最近访问的文件

        Args:
            user_id: 用户ID
            limit: 返回数量限制

        Returns:
            List[Dict]: 最近文件列表
        """
        with self.db.get_cursor() as cursor:
            cursor.execute('''
                SELECT action, resource_type, details, created_at
                FROM logs
                WHERE user_id = ? AND action IN ('file_view', 'file_upload', 'file_download')
                ORDER BY created_at DESC
                LIMIT ?
            ''', (user_id, limit))
            rows = cursor.fetchall()
            return [
                {
                    'action': r[0],
                    'resource_type': r[1],
                    'details': r[2],
                    'created_at': r[3]
                }
                for r in rows
            ]
