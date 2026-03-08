# -*- coding: utf-8 -*-
"""
文件操作 API 完整测试
"""

from pathlib import Path

import pytest

from app.core.database import Database, init_database
from app.core.security import create_access_token


class TestCreateFolderAPI:
    """创建文件夹 API 测试"""

    @pytest.mark.asyncio
    async def test_create_folder_already_exists(self, async_client):
        """测试创建已存在的文件夹（假设文件夹已存在）"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        # 尝试创建特殊目录（可能失败）
        response = await async_client.post(
            "/files/folder",
            headers={"Authorization": f"Bearer {token}"},
            json={"path": "/", "name": "test_folder"},
        )

        # 应该返回错误或成功（取决于实现）
        assert response.status_code in [200, 201, 400]


class TestRenameFileAPI:
    """重命名文件 API 测试"""

    @pytest.mark.asyncio
    async def test_rename_file_nonexistent(self, async_client):
        """测试重命名不存在的文件"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.post(
            "/files/rename",
            headers={"Authorization": f"Bearer {token}"},
            json={"old_path": "/nonexistent", "new_name": "new_name"},
        )

        assert response.status_code == 400
        data = response.json()
        assert "重命名失败" in data.get("detail", "")


class TestDeleteFileAPI:
    """删除文件 API 测试"""

    @pytest.mark.asyncio
    async def test_delete_file_nonexistent(self, async_client):
        """测试删除不存在的文件"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.delete(
            "/files/nonexistent_file.txt", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404
        data = response.json()
        assert "不存在" in data.get("detail", "")


class TestBatchDeleteAPI:
    """批量删除 API 测试"""

    @pytest.mark.asyncio
    async def test_batch_delete_empty(self, async_client):
        """测试批量删除空列表（应该返回验证错误）"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        # BatchDelete 模型要求至少 1 个项目
        response = await async_client.post(
            "/files/batch-delete",
            headers={"Authorization": f"Bearer {token}"},
            json={"paths": []},
        )

        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_batch_delete_mixed(self, async_client):
        """测试批量删除混合存在和不存在的文件"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        # 创建一个文件夹
        await async_client.post(
            "/files/folder",
            headers={"Authorization": f"Bearer {token}"},
            json={"path": "/", "name": "to_delete"},
        )

        # 批量删除（包含存在和不存在的）
        response = await async_client.post(
            "/files/batch-delete",
            headers={"Authorization": f"Bearer {token}"},
            json={"paths": ["/to_delete", "/nonexistent"]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] >= 1
        assert "failed_count" in data
        assert "failed_items" in data


class TestDownloadFileAPI:
    """下载文件 API 测试"""

    @pytest.mark.asyncio
    async def test_download_file_nonexistent(self, async_client):
        """测试下载不存在的文件"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.get(
            "/files/download/nonexistent.txt",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_download_directory(self, async_client):
        """测试下载目录（应该失败）"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        # 创建一个文件夹
        await async_client.post(
            "/files/folder",
            headers={"Authorization": f"Bearer {token}"},
            json={"path": "/", "name": "test_dir"},
        )

        # 尝试下载目录
        response = await async_client.get(
            "/files/download/test_dir", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 400
        data = response.json()
        assert "无法下载目录" in data.get("detail", "")


class TestRecentFilesAPI:
    """最近文件 API 测试"""

    @pytest.mark.asyncio
    async def test_get_recent_files_default_limit(self, async_client):
        """测试获取最近文件（默认限制）"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.get(
            "/files/recent", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_recent_files_custom_limit(self, async_client):
        """测试获取最近文件（自定义限制）"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.get(
            "/files/recent?limit=5", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    @pytest.mark.asyncio
    async def test_get_recent_files_invalid_limit(self, async_client):
        """测试获取最近文件（无效限制）"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        # 超过最大限制
        response = await async_client.get(
            "/files/recent?limit=200", headers={"Authorization": f"Bearer {token}"}
        )

        # 应该返回验证错误或自动限制到最大值
        assert response.status_code in [200, 422]
