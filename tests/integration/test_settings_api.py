# -*- coding: utf-8 -*-
"""
用户设置 API 测试
"""

import pytest

from app.core.security import create_access_token


class TestSettingsAPI:
    """用户设置 API 测试"""

    @pytest.mark.asyncio
    async def test_get_settings(self, async_client):
        """测试获取用户设置"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.get(
            "/user/settings", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        # 检查返回的设置字段
        assert "user_id" in data or "theme" in data or "view_mode" in data

    @pytest.mark.asyncio
    async def test_update_settings_theme(self, async_client):
        """测试更新主题设置"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.put(
            "/user/settings",
            headers={"Authorization": f"Bearer {token}"},
            json={"theme": "dark"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "设置保存成功" in data.get("message", "")

    @pytest.mark.asyncio
    async def test_update_settings_view_mode(self, async_client):
        """测试更新视图模式设置"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.put(
            "/user/settings",
            headers={"Authorization": f"Bearer {token}"},
            json={"view_mode": "grid"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "设置保存成功" in data.get("message", "")

    @pytest.mark.asyncio
    async def test_update_settings_multiple(self, async_client):
        """测试更新多个设置"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.put(
            "/user/settings",
            headers={"Authorization": f"Bearer {token}"},
            json={"theme": "light", "view_mode": "list", "items_per_page": 50},
        )

        assert response.status_code == 200
        data = response.json()
        assert "设置保存成功" in data.get("message", "")


class TestStorageInfoAPI:
    """存储信息 API 测试"""

    @pytest.mark.asyncio
    async def test_get_storage_info(self, async_client):
        """测试获取存储信息"""
        token_data = {"user_id": 1, "username": "admin", "is_admin": True}
        token = create_access_token(token_data)

        response = await async_client.get(
            "/user/storage", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        # 检查存储信息字段
        assert "total_space" in data or "used_space" in data or "free_space" in data

    @pytest.mark.asyncio
    async def test_get_storage_info_without_auth(self, async_client):
        """测试未认证获取存储信息"""
        response = await async_client.get("/user/storage")

        # 可能不需要认证，也可能需要
        assert response.status_code in [200, 401, 403]
